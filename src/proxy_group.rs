use std::sync::Arc;

use anyhow::{anyhow, bail};

use crate::protocol::Protocol;

#[derive(Clone, Debug)]
pub struct ProxyGroup {
    pub name: String,
    pub http: String,
    pub socks5: String,
}

impl ProxyGroup {
    pub fn endpoint(&self, protocol: Protocol) -> &str {
        match protocol {
            Protocol::Http => &self.http,
            Protocol::Socks5 => &self.socks5,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ProxyGroupId(usize);

impl ProxyGroupId {
    pub(crate) const fn new(index: usize) -> Self {
        Self(index)
    }
}

#[derive(Clone)]
pub struct ProxyGroups {
    groups: Arc<Vec<ProxyGroup>>,
    default: ProxyGroupId,
}

impl ProxyGroups {
    pub fn new(groups: Vec<ProxyGroup>, default_name: &str) -> anyhow::Result<Self> {
        if groups.is_empty() {
            bail!("at least one proxy group is required");
        }

        for (index, group) in groups.iter().enumerate() {
            if group.name.is_empty() {
                bail!("proxy group name must not be empty");
            }
            if group.http.is_empty() {
                bail!("proxy group '{}' has an empty http address", group.name);
            }
            if group.socks5.is_empty() {
                bail!("proxy group '{}' has an empty socks5 address", group.name);
            }
            if groups[..index]
                .iter()
                .any(|other| other.name.as_str() == group.name.as_str())
            {
                bail!("duplicate proxy group '{}'", group.name);
            }
        }

        let default = groups
            .iter()
            .position(|group| group.name.as_str() == default_name)
            .map(ProxyGroupId::new)
            .ok_or_else(|| anyhow!("default proxy group '{default_name}' is not configured"))?;

        Ok(Self {
            groups: Arc::new(groups),
            default,
        })
    }

    pub fn get(&self, id: ProxyGroupId) -> &ProxyGroup {
        &self.groups[id.0]
    }

    pub fn default_id(&self) -> ProxyGroupId {
        self.default
    }

    pub fn default_group(&self) -> &ProxyGroup {
        self.get(self.default)
    }

    pub fn resolve(&self, name: Option<&str>) -> anyhow::Result<ProxyGroupId> {
        let Some(name) = name else {
            return Ok(self.default);
        };

        self.groups
            .iter()
            .position(|group| group.name.as_str() == name)
            .map(ProxyGroupId::new)
            .ok_or_else(|| {
                let available = self
                    .groups
                    .iter()
                    .map(|group| group.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                anyhow!("proxy group '{name}' not found; available: {available}")
            })
    }

    pub fn iter(&self) -> impl Iterator<Item = &ProxyGroup> {
        self.groups.iter()
    }
}
