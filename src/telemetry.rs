//! OpenTelemetry metric wiring: resource, OTLP/HTTP exporter, periodic reader
//! and the `metrics` recorder bridging into it.
//!
//! There is nothing span-shaped in a proxy hop worth exporting, so this is
//! metrics only. Constructed once in `main` before the listeners start.
//! Without `otel.endpoint` (or `OTEL_EXPORTER_OTLP_ENDPOINT`) nothing is built
//! at all: every `metrics` call in the crate then records into the facade's
//! built-in no-op recorder and no exporter thread exists.

use std::{
    collections::HashMap,
    net::{IpAddr, UdpSocket},
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use log::info;
use metrics::KeyName;
use metrics_exporter_otel::OpenTelemetryRecorder;
use opentelemetry::KeyValue;
use opentelemetry::metrics::MeterProvider as _;
use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider, Temporality};
use serde::{Deserialize, Deserializer};

use crate::metrics::{describe_metrics, histogram_bounds};

/// Standard OTLP base-URL variable, honored when `otel.endpoint` is unset.
const OTEL_ENDPOINT_ENV: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";

/// The instrumentation scope the recorder's meter is created under.
const SCOPE_NAME: &str = "autoproxy";

/// Bound on one export request, so a wedged collector cannot pin the reader's
/// thread indefinitely.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(10);

/// OpenTelemetry settings. The whole block is optional: without an endpoint
/// the process exports nothing and starts no exporter machinery.
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct OtelConfig {
    /// OTLP/HTTP collector base URL, e.g. `http://127.0.0.1:4318`. Unset (or
    /// empty) disables metrics. When unset, `OTEL_EXPORTER_OTLP_ENDPOINT` is
    /// honored as a fallback so a collector can be smoke-tested without
    /// editing the config file.
    #[serde(default, deserialize_with = "parse_otel_endpoint")]
    pub endpoint: Option<String>,
    /// `http-proto` (default, the OTLP standard and what the crate defaults
    /// to) or `http-json`, which is inspectable with curl during bring-up.
    #[serde(deserialize_with = "parse_otel_protocol")]
    pub protocol: OtelProtocol,
    /// Appended to `endpoint`. Point the endpoint at the base URL, not at a
    /// signal URL: a full signal URL given here is used verbatim by the SDK,
    /// so the path would then be appended to it.
    pub metrics_path: String,
    /// The `service.name` resource attribute every point carries.
    pub service_name: String,
    /// The `service.instance.id` resource attribute. Unset means the device's
    /// outbound IP, determined by a UDP route lookup to a public resolver.
    /// Set it when that route does not identify the device (a tunnel or a
    /// multi-homed host, for instance).
    pub instance_id: Option<String>,
    /// How often the metric reader exports.
    pub export_interval_secs: u64,
    /// Extra OTLP request headers, for a collector that wants auth.
    pub headers: HashMap<String, String>,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            endpoint: None,
            protocol: OtelProtocol::HttpProto,
            metrics_path: "/v1/metrics".into(),
            service_name: "autoproxy".into(),
            instance_id: None,
            export_interval_secs: 15,
            headers: HashMap::new(),
        }
    }
}

impl OtelConfig {
    /// The effective endpoint: the configured one, or the standard
    /// environment variable. Validated by [`parse_otel_endpoint`] at load
    /// time for the configured value; the environment fallback is taken as it
    /// comes.
    pub fn resolved_endpoint(&self) -> Option<String> {
        match self.endpoint.as_deref() {
            Some(endpoint) if !endpoint.is_empty() => Some(endpoint.to_string()),
            _ => std::env::var(OTEL_ENDPOINT_ENV)
                .ok()
                .filter(|value| !value.is_empty()),
        }
    }
}

/// Transport for the OTLP exporter. The default matches `opentelemetry-otlp`'s
/// own default, so an untouched config uses the standard wire format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OtelProtocol {
    #[default]
    HttpProto,
    HttpJson,
}

/// Telemetry is installed and running. Holds the meter provider so it outlives
/// [`Telemetry::init`]: dropping an SDK provider shuts its reader down, and the
/// `metrics` recorder keeps only a meter handle, not the provider behind it.
pub struct Telemetry {
    /// Never read: held so the periodic reader keeps exporting.
    _meter: SdkMeterProvider,
}

impl Telemetry {
    /// Build the provider, install the recorder and describe the metric
    /// names. Returns `None` when no endpoint is configured: the process then
    /// runs on the facade's no-op recorder.
    ///
    /// `version` is recorded as the `service.version` resource attribute and
    /// is a parameter so this module does not depend on the build metadata.
    pub fn init(config: &OtelConfig, version: &str) -> Result<Option<Self>> {
        let Some(endpoint) = config.resolved_endpoint() else {
            info!("OTel metrics: off");
            return Ok(None);
        };
        let url = signal_url(&endpoint, &config.metrics_path);
        let interval = config.export_interval_secs.max(1);
        let instance_id = configured_instance_id(config)
            .or_else(|| detect_device_ip().map(|ip| ip.to_string()))
            .unwrap_or_else(|| {
                log::warn!(
                    "OTel metrics: cannot determine the device IP, set otel.instance_id \
                     so replicas on different devices do not share a series"
                );
                "unknown".to_string()
            });

        let resource = Resource::builder()
            .with_service_name(config.service_name.clone())
            .with_attribute(KeyValue::new("service.version", version.to_string()))
            .with_attribute(KeyValue::new("service.instance.id", instance_id.clone()))
            .build();
        let exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_endpoint(url.clone())
            .with_protocol(protocol(config.protocol))
            .with_timeout(EXPORT_TIMEOUT)
            .with_headers(config.headers.clone())
            // Cumulative, like the collector's ClickHouse exporter expects: an
            // interval's value is the difference between consecutive points.
            .with_temporality(Temporality::Cumulative)
            .build()
            .context("build OTLP metric exporter")?;
        let reader = PeriodicReader::builder(exporter)
            .with_interval(Duration::from_secs(interval))
            .build();
        let provider = SdkMeterProvider::builder()
            .with_resource(resource)
            .with_reader(reader)
            .build();

        let recorder = OpenTelemetryRecorder::new(provider.meter(SCOPE_NAME));
        // Buckets and descriptions must be installed before the first
        // recording: a recorder cannot restate them once a metric exists. The
        // descriptions go through the global recorder, so they are written
        // after it is installed rather than before.
        for (name, bounds) in histogram_bounds() {
            recorder.set_histogram_bounds(&KeyName::from_const_str(name), bounds);
        }
        metrics::set_global_recorder(recorder)
            .map_err(|error| anyhow!("install metrics recorder: {error}"))?;
        describe_metrics();

        info!(
            "OTel metrics: {} (service {}, instance {}, every {}s)",
            url, config.service_name, instance_id, interval
        );
        Ok(Some(Self { _meter: provider }))
    }
}

/// The configured instance id, trimmed, or `None` when it is unset or blank.
fn configured_instance_id(config: &OtelConfig) -> Option<String> {
    config
        .instance_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
}

/// The device's outbound IP. A connected UDP socket sends no packet, it only
/// asks the routing table which local address reaches a public resolver, so
/// this does not depend on the collector URL or on DNS.
fn detect_device_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:53").ok()?;
    let ip = socket.local_addr().ok()?.ip();
    (!ip.is_unspecified()).then_some(ip)
}

/// One signal's URL: the configured base plus its path, with a single slash
/// between them. The SDK appends nothing to an explicitly configured endpoint,
/// so the path has to be joined here.
fn signal_url(endpoint: &str, path: &str) -> String {
    let endpoint = endpoint.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    match path.is_empty() {
        true => endpoint.to_string(),
        false => format!("{endpoint}/{path}"),
    }
}

fn protocol(protocol: OtelProtocol) -> Protocol {
    match protocol {
        OtelProtocol::HttpJson => Protocol::HttpJson,
        OtelProtocol::HttpProto => Protocol::HttpBinary,
    }
}

fn parse_otel_protocol<'de, D>(deserializer: D) -> std::result::Result<OtelProtocol, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    match raw.as_str() {
        "http-json" => Ok(OtelProtocol::HttpJson),
        "http-proto" => Ok(OtelProtocol::HttpProto),
        other => Err(serde::de::Error::custom(format!(
            "invalid otel.protocol {other:?}: expected http-json or http-proto"
        ))),
    }
}

/// Validated at parse time so a typo fails at startup, like `listen`: an
/// endpoint must be an absolute `http(s)` URL without query or fragment.
fn parse_otel_endpoint<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    let Some(endpoint) = raw.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let rest = match endpoint.split_once("://") {
        Some(("http" | "https", rest)) => rest,
        _ => {
            return Err(serde::de::Error::custom(format!(
                "invalid otel.endpoint {endpoint:?}: expected an http(s) URL"
            )));
        }
    };
    if rest.is_empty() || rest.starts_with('/') {
        return Err(serde::de::Error::custom(format!(
            "invalid otel.endpoint {endpoint:?}: expected a host"
        )));
    }
    if endpoint.contains('?') || endpoint.contains('#') {
        return Err(serde::de::Error::custom(format!(
            "invalid otel.endpoint {endpoint:?}: no query or fragment"
        )));
    }
    Ok(Some(endpoint))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    struct Wrapper {
        #[serde(default)]
        otel: OtelConfig,
    }

    #[test]
    fn signal_url_joins_with_exactly_one_slash() {
        assert_eq!(
            signal_url("http://10.0.0.36:4318", "/v1/metrics"),
            "http://10.0.0.36:4318/v1/metrics"
        );
        assert_eq!(
            signal_url("http://10.0.0.36:4318/", "/v1/metrics"),
            "http://10.0.0.36:4318/v1/metrics"
        );
        // An empty path leaves the endpoint alone (a collector mounted at the root).
        assert_eq!(
            signal_url("http://10.0.0.36:4318/", "/"),
            "http://10.0.0.36:4318"
        );
    }

    #[test]
    fn an_empty_instance_id_falls_back_to_detection() {
        let wrapper: Wrapper = toml::from_str("otel = { instance_id = \"   \" }").unwrap();
        assert_eq!(configured_instance_id(&wrapper.otel), None);

        let wrapper: Wrapper = toml::from_str("otel = { instance_id = \" 10.0.0.37 \" }").unwrap();
        assert_eq!(
            configured_instance_id(&wrapper.otel).as_deref(),
            Some("10.0.0.37")
        );
    }

    #[test]
    fn protocol_maps_to_the_otlp_protocol() {
        assert!(matches!(
            protocol(OtelProtocol::HttpJson),
            Protocol::HttpJson
        ));
        assert!(matches!(
            protocol(OtelProtocol::HttpProto),
            Protocol::HttpBinary
        ));
    }

    #[test]
    fn a_missing_block_disables_metrics() {
        let wrapper: Wrapper = toml::from_str("").unwrap();
        assert_eq!(wrapper.otel.resolved_endpoint(), None);
        assert_eq!(wrapper.otel.protocol, OtelProtocol::HttpProto);
        assert_eq!(wrapper.otel.metrics_path, "/v1/metrics");
        assert_eq!(wrapper.otel.service_name, "autoproxy");
        assert_eq!(wrapper.otel.instance_id, None);
        assert_eq!(wrapper.otel.export_interval_secs, 15);
    }

    #[test]
    fn the_otel_block_parses_and_its_typos_fail_fast() {
        let wrapper: Wrapper = toml::from_str(
            "otel = { endpoint = \"http://10.0.0.36:4318/\", protocol = \"http-json\", \
             service_name = \"autoproxy-mock\", instance_id = \"10.0.0.37\", \
             export_interval_secs = 5, \
             headers = { authorization = \"Bearer x\" } }",
        )
        .unwrap();
        assert_eq!(
            wrapper.otel.resolved_endpoint().as_deref(),
            Some("http://10.0.0.36:4318/")
        );
        assert!(matches!(wrapper.otel.protocol, OtelProtocol::HttpJson));
        assert_eq!(wrapper.otel.service_name, "autoproxy-mock");
        assert_eq!(
            configured_instance_id(&wrapper.otel).as_deref(),
            Some("10.0.0.37")
        );
        assert_eq!(wrapper.otel.export_interval_secs, 5);
        assert_eq!(
            wrapper
                .otel
                .headers
                .get("authorization")
                .map(String::as_str),
            Some("Bearer x")
        );

        // An empty endpoint is the same as no endpoint at all.
        let wrapper: Wrapper = toml::from_str("otel = { endpoint = \"\" }").unwrap();
        assert_eq!(wrapper.otel.resolved_endpoint(), None);

        for bad in ["10.0.0.36:4318", "grpc://10.0.0.36:4317", "http://"] {
            let error = toml::from_str::<Wrapper>(&format!("otel = {{ endpoint = \"{bad}\" }}"))
                .unwrap_err()
                .to_string();
            assert!(error.contains("otel.endpoint"), "{bad}: {error}");
        }

        let error = toml::from_str::<Wrapper>("otel = { protocol = \"grpc\" }")
            .unwrap_err()
            .to_string();
        assert!(error.contains("otel.protocol"), "{error}");
    }
}
