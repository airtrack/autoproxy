-- Grafana SQL for the metrics autoproxy reports over OTLP.
--
-- Schema: the OpenTelemetry collector's clickhouseexporter tables, in database
-- `otel` -- otel_metrics_sum (counters, column Value), otel_metrics_histogram
-- (Count / Sum / BucketCounts / ExplicitBounds), otel_metrics_gauge (Value).
-- Labels live in the Attributes map: Attributes['key'], and a key a series does
-- not carry reads as ''. ddl: collector clickhouseexporter internal/sqltemplates.
--
-- Macros are the ClickHouse plugin's: $__timeFilter(TimeUnix) expands to the
-- panel's range, $__timeInterval(TimeUnix) to its bucket, $__interval_s to the
-- bucket in seconds.
--
-- Every counter is CUMULATIVE -- autoproxy exports with Temporality::Cumulative,
-- once every otel.export_interval_secs (15 by default) -- so an interval's value
-- is the difference between consecutive points. That difference is taken with
-- lagInFrame over (MetricName, the whole label map), never with max-min inside a
-- bucket: a Grafana bucket is usually one export wide, and a single point has no
-- difference to give (every panel would read 0). Partitioning by MetricName as
-- well as the labels keeps two metrics that carry the same labels, and two
-- series that differ in any label, from being differenced against each other.
-- greatest(..., 0) absorbs a process restart, where every cumulative value drops
-- back to zero.
--
-- Gauges (active connections, in-flight queries, cache size) are levels, not
-- totals: they are read with argMax inside the bucket, never differenced.
--
-- The first bucket of the selected range reads 0: it has no predecessor. Give
-- each panel a Min interval at or above otel.export_interval_secs so a bucket
-- never falls below one export (the generated dashboard uses 15s).
--
-- The first section is different on purpose: its panels carry NO time filter and
-- run a running total over the whole history, so each line keeps climbing across
-- restarts and across the week you are looking at. The panel's range only
-- decides which part of that curve is drawn -- the value at any point is the
-- all-time total at that moment, not the total within the range. Those panels
-- are also the only ones that carry several series on purpose.
--
-- Each panel is one statement preceded by a header:
--   -- <title> | <view> | <unit>
-- where view is timeseries | barchart | stat and unit is a Grafana unit id.
-- docs/grafana-metrics-dashboard.json is generated from these headers.
--
-- ServiceName is the literal 'autoproxy' (otel.service_name) so a statement can
-- be pasted into clickhouse-client or Explore as it stands, while the generated
-- dashboard reads the same statements with a ${service} variable.



-- == Totals (cumulative, since the first export) ==

-- Connections, total | timeseries | short
SELECT time,
       pair.1 AS series,
       sum(pair.2) OVER (PARTITION BY pair.1 ORDER BY time) AS connections
FROM (
    SELECT $__timeInterval(TimeUnix) AS time,
           [('total', sum(delta)),
            ('http', sumIf(delta, Attributes['protocol'] = 'http')),
            ('socks5', sumIf(delta, Attributes['protocol'] = 'socks5'))] AS pairs
    FROM (
        SELECT TimeUnix,
               Attributes,
               greatest(Value - lagInFrame(Value, 1, Value)
                        OVER (PARTITION BY MetricName, toString(Attributes) ORDER BY TimeUnix), 0) AS delta
        FROM otel.otel_metrics_sum
        WHERE MetricName = 'autoproxy.proxy.connections'
          AND ServiceName = 'autoproxy'
    )
    GROUP BY time
)
ARRAY JOIN pairs AS pair
ORDER BY time;

-- DNS queries, total | timeseries | short
SELECT time,
       pair.1 AS series,
       sum(pair.2) OVER (PARTITION BY pair.1 ORDER BY time) AS queries
FROM (
    SELECT $__timeInterval(TimeUnix) AS time,
           [('total', sum(delta)),
            ('hosts', sumIf(delta, Attributes['path'] = 'hosts')),
            ('direct', sumIf(delta, Attributes['path'] = 'direct')),
            ('proxy', sumIf(delta, Attributes['path'] = 'proxy')),
            ('block', sumIf(delta, Attributes['path'] = 'block'))] AS pairs
    FROM (
        SELECT TimeUnix,
               Attributes,
               greatest(Value - lagInFrame(Value, 1, Value)
                        OVER (PARTITION BY MetricName, toString(Attributes) ORDER BY TimeUnix), 0) AS delta
        FROM otel.otel_metrics_sum
        WHERE MetricName = 'autoproxy.dns.queries'
          AND ServiceName = 'autoproxy'
    )
    GROUP BY time
)
ARRAY JOIN pairs AS pair
ORDER BY time;


-- == Proxy connections ==

-- Connections by protocol | barchart | short
SELECT time,
       protocol,
       sum(delta) AS connections
FROM (
    SELECT $__timeInterval(TimeUnix) AS time,
           Attributes['protocol'] AS protocol,
           greatest(Value - lagInFrame(Value, 1, Value)
                    OVER (PARTITION BY MetricName, toString(Attributes) ORDER BY TimeUnix), 0) AS delta
    FROM otel.otel_metrics_sum
    WHERE MetricName = 'autoproxy.proxy.connections'
      AND ServiceName = 'autoproxy'
      AND $__timeFilter(TimeUnix)
)
GROUP BY time, protocol
ORDER BY time;

-- Failed connections | timeseries | short
SELECT time,
       protocol,
       sum(delta) AS failed
FROM (
    SELECT $__timeInterval(TimeUnix) AS time,
           Attributes['protocol'] AS protocol,
           greatest(Value - lagInFrame(Value, 1, Value)
                    OVER (PARTITION BY MetricName, toString(Attributes) ORDER BY TimeUnix), 0) AS delta
    FROM otel.otel_metrics_sum
    WHERE MetricName = 'autoproxy.proxy.connections'
      AND Attributes['outcome'] = 'error'
      AND ServiceName = 'autoproxy'
      AND $__timeFilter(TimeUnix)
)
GROUP BY time, protocol
ORDER BY time;

-- Connection duration p95 | timeseries | s
SELECT time,
       series,
       if(arraySum(counts) = 0, NULL,
          arrayElement(bounds,
                       least(arrayCount(x -> x < 0.95 * arraySum(counts),
                                        arrayCumSum(counts)) + 1,
                             length(bounds)))) AS p95
FROM (
    SELECT time,
           series,
           bounds,
           arrayMap((hi, lo) -> greatest(toInt64(hi) - toInt64(lo), 0),
                    last_counts,
                    lagInFrame(last_counts, 1, first_counts)
                        OVER (PARTITION BY series ORDER BY time)) AS counts
    FROM (
        SELECT $__timeInterval(TimeUnix) AS time,
               Attributes['protocol'] AS series,
               argMax(BucketCounts, TimeUnix) AS last_counts,
               argMin(BucketCounts, TimeUnix) AS first_counts,
               any(ExplicitBounds) AS bounds
        FROM otel.otel_metrics_histogram
        WHERE MetricName = 'autoproxy.proxy.connection.duration'
          AND ServiceName = 'autoproxy'
          AND $__timeFilter(TimeUnix)
        GROUP BY time, series
    )
)
ORDER BY time;

-- Active connections | timeseries | short
SELECT $__timeInterval(TimeUnix) AS time,
       Attributes['protocol'] AS protocol,
       argMax(Value, TimeUnix) AS active
FROM otel.otel_metrics_gauge
WHERE MetricName = 'autoproxy.proxy.active_connections'
  AND ServiceName = 'autoproxy'
  AND $__timeFilter(TimeUnix)
GROUP BY time, protocol
ORDER BY time;

-- Connection success ratio | timeseries | percentunit
SELECT time,
       sum(ok) AS ok_connections,
       sum(failed) AS failed_connections,
       if(sum(ok) + sum(failed) > 0, sum(ok) / (sum(ok) + sum(failed)), 0) AS success_ratio
FROM (
    SELECT $__timeInterval(TimeUnix) AS time,
           toString(Attributes) AS series,
           greatest(maxIf(delta, Attributes['outcome'] = 'ok'), 0) AS ok,
           greatest(maxIf(delta, Attributes['outcome'] = 'error'), 0) AS failed
    FROM (
        SELECT TimeUnix,
               Attributes,
               greatest(Value - lagInFrame(Value, 1, Value)
                        OVER (PARTITION BY MetricName, toString(Attributes) ORDER BY TimeUnix), 0) AS delta
        FROM otel.otel_metrics_sum
        WHERE MetricName = 'autoproxy.proxy.connections'
          AND ServiceName = 'autoproxy'
          AND $__timeFilter(TimeUnix)
    )
    GROUP BY time, series
)
GROUP BY time
ORDER BY time;


-- == Routing ==

-- Connect decisions by path | barchart | short
SELECT time,
       path,
       sum(delta) AS decisions
FROM (
    SELECT $__timeInterval(TimeUnix) AS time,
           Attributes['path'] AS path,
           greatest(Value - lagInFrame(Value, 1, Value)
                    OVER (PARTITION BY MetricName, toString(Attributes) ORDER BY TimeUnix), 0) AS delta
    FROM otel.otel_metrics_sum
    WHERE MetricName = 'autoproxy.proxy.connect.decisions'
      AND ServiceName = 'autoproxy'
      AND $__timeFilter(TimeUnix)
)
GROUP BY time, path
ORDER BY time;

-- Proxy share of decisions | timeseries | percentunit
SELECT time,
       sum(via_proxy) AS proxy_decisions,
       sum(decisions) AS total_decisions,
       if(sum(decisions) > 0, sum(via_proxy) / sum(decisions), 0) AS proxy_ratio
FROM (
    SELECT $__timeInterval(TimeUnix) AS time,
           toString(Attributes) AS series,
           greatest(maxIf(delta, Attributes['path'] = 'proxy'), 0) AS via_proxy,
           greatest(sum(delta), 0) AS decisions
    FROM (
        SELECT TimeUnix,
               Attributes,
               greatest(Value - lagInFrame(Value, 1, Value)
                        OVER (PARTITION BY MetricName, toString(Attributes) ORDER BY TimeUnix), 0) AS delta
        FROM otel.otel_metrics_sum
        WHERE MetricName = 'autoproxy.proxy.connect.decisions'
          AND ServiceName = 'autoproxy'
          AND $__timeFilter(TimeUnix)
    )
    GROUP BY time, series
)
GROUP BY time
ORDER BY time;


-- == DNS ==

-- DNS queries by type | barchart | short
SELECT time,
       query_type,
       sum(delta) AS queries
FROM (
    SELECT $__timeInterval(TimeUnix) AS time,
           Attributes['type'] AS query_type,
           greatest(Value - lagInFrame(Value, 1, Value)
                    OVER (PARTITION BY MetricName, toString(Attributes) ORDER BY TimeUnix), 0) AS delta
    FROM otel.otel_metrics_sum
    WHERE MetricName = 'autoproxy.dns.queries'
      AND ServiceName = 'autoproxy'
      AND $__timeFilter(TimeUnix)
)
GROUP BY time, query_type
ORDER BY time;

-- DNS queries by answer path | barchart | short
SELECT time,
       path,
       sum(delta) AS queries
FROM (
    SELECT $__timeInterval(TimeUnix) AS time,
           Attributes['path'] AS path,
           greatest(Value - lagInFrame(Value, 1, Value)
                    OVER (PARTITION BY MetricName, toString(Attributes) ORDER BY TimeUnix), 0) AS delta
    FROM otel.otel_metrics_sum
    WHERE MetricName = 'autoproxy.dns.queries'
      AND ServiceName = 'autoproxy'
      AND $__timeFilter(TimeUnix)
)
GROUP BY time, path
ORDER BY time;

-- Upstream resolution p95 | timeseries | s
SELECT time,
       series,
       if(arraySum(counts) = 0, NULL,
          arrayElement(bounds,
                       least(arrayCount(x -> x < 0.95 * arraySum(counts),
                                        arrayCumSum(counts)) + 1,
                             length(bounds)))) AS p95
FROM (
    SELECT time,
           series,
           bounds,
           arrayMap((hi, lo) -> greatest(toInt64(hi) - toInt64(lo), 0),
                    last_counts,
                    lagInFrame(last_counts, 1, first_counts)
                        OVER (PARTITION BY series ORDER BY time)) AS counts
    FROM (
        SELECT $__timeInterval(TimeUnix) AS time,
               Attributes['path'] AS series,
               argMax(BucketCounts, TimeUnix) AS last_counts,
               argMin(BucketCounts, TimeUnix) AS first_counts,
               any(ExplicitBounds) AS bounds
        FROM otel.otel_metrics_histogram
        WHERE MetricName = 'autoproxy.dns.upstream.duration'
          AND ServiceName = 'autoproxy'
          AND $__timeFilter(TimeUnix)
        GROUP BY time, series
    )
)
ORDER BY time;

-- Upstream errors by path | timeseries | short
SELECT time,
       path,
       sum(delta) AS errors
FROM (
    SELECT $__timeInterval(TimeUnix) AS time,
           Attributes['path'] AS path,
           greatest(Value - lagInFrame(Value, 1, Value)
                    OVER (PARTITION BY MetricName, toString(Attributes) ORDER BY TimeUnix), 0) AS delta
    FROM otel.otel_metrics_sum
    WHERE MetricName = 'autoproxy.dns.upstream.errors'
      AND ServiceName = 'autoproxy'
      AND $__timeFilter(TimeUnix)
)
GROUP BY time, path
ORDER BY time;

-- Upstream queries in flight | timeseries | short
SELECT $__timeInterval(TimeUnix) AS time,
       argMax(Value, TimeUnix) AS in_flight
FROM otel.otel_metrics_gauge
WHERE MetricName = 'autoproxy.dns.in_flight'
  AND ServiceName = 'autoproxy'
  AND $__timeFilter(TimeUnix)
GROUP BY time
ORDER BY time;

-- Path cache entries | timeseries | short
SELECT $__timeInterval(TimeUnix) AS time,
       argMax(Value, TimeUnix) AS entries
FROM otel.otel_metrics_gauge
WHERE MetricName = 'autoproxy.dns.cache.entries'
  AND ServiceName = 'autoproxy'
  AND $__timeFilter(TimeUnix)
GROUP BY time
ORDER BY time;

-- Path cache lookups by result | barchart | short
SELECT time,
       result,
       sum(delta) AS lookups
FROM (
    SELECT $__timeInterval(TimeUnix) AS time,
           Attributes['result'] AS result,
           greatest(Value - lagInFrame(Value, 1, Value)
                    OVER (PARTITION BY MetricName, toString(Attributes) ORDER BY TimeUnix), 0) AS delta
    FROM otel.otel_metrics_sum
    WHERE MetricName = 'autoproxy.dns.cache.lookups'
      AND ServiceName = 'autoproxy'
      AND $__timeFilter(TimeUnix)
)
GROUP BY time, result
ORDER BY time;

-- Path cache hit ratio | timeseries | percentunit
SELECT time,
       sum(hits) AS cache_hits,
       sum(misses) AS cache_misses,
       if(sum(hits) + sum(misses) > 0, sum(hits) / (sum(hits) + sum(misses)), 0) AS hit_ratio
FROM (
    SELECT $__timeInterval(TimeUnix) AS time,
           toString(Attributes) AS series,
           greatest(maxIf(delta, Attributes['result'] = 'hit'), 0) AS hits,
           greatest(maxIf(delta, Attributes['result'] = 'miss'), 0) AS misses
    FROM (
        SELECT TimeUnix,
               Attributes,
               greatest(Value - lagInFrame(Value, 1, Value)
                        OVER (PARTITION BY MetricName, toString(Attributes) ORDER BY TimeUnix), 0) AS delta
        FROM otel.otel_metrics_sum
        WHERE MetricName = 'autoproxy.dns.cache.lookups'
          AND ServiceName = 'autoproxy'
          AND $__timeFilter(TimeUnix)
    )
    GROUP BY time, series
)
GROUP BY time
ORDER BY time;


-- == SOCKS5 UDP ==

-- UDP packets by direction | timeseries | short
SELECT time,
       direction,
       sum(delta) AS packets
FROM (
    SELECT $__timeInterval(TimeUnix) AS time,
           Attributes['direction'] AS direction,
           greatest(Value - lagInFrame(Value, 1, Value)
                    OVER (PARTITION BY MetricName, toString(Attributes) ORDER BY TimeUnix), 0) AS delta
    FROM otel.otel_metrics_sum
    WHERE MetricName = 'autoproxy.proxy.udp.packets'
      AND ServiceName = 'autoproxy'
      AND $__timeFilter(TimeUnix)
)
GROUP BY time, direction
ORDER BY time;

-- UDP bytes by direction | timeseries | bytes
SELECT time,
       direction,
       sum(delta) AS bytes
FROM (
    SELECT $__timeInterval(TimeUnix) AS time,
           Attributes['direction'] AS direction,
           greatest(Value - lagInFrame(Value, 1, Value)
                    OVER (PARTITION BY MetricName, toString(Attributes) ORDER BY TimeUnix), 0) AS delta
    FROM otel.otel_metrics_sum
    WHERE MetricName = 'autoproxy.proxy.udp.bytes'
      AND ServiceName = 'autoproxy'
      AND $__timeFilter(TimeUnix)
)
GROUP BY time, direction
ORDER BY time;

-- Blocked UDP packets in range | stat | short
SELECT sum(delta) AS blocked_udp_packets
FROM (
    SELECT greatest(Value - lagInFrame(Value, 1, Value)
                    OVER (PARTITION BY MetricName, toString(Attributes) ORDER BY TimeUnix), 0) AS delta
    FROM otel.otel_metrics_sum
    WHERE MetricName = 'autoproxy.proxy.udp.blocked'
      AND ServiceName = 'autoproxy'
      AND $__timeFilter(TimeUnix)
);
