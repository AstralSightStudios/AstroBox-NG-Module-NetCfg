use anyhow::{Context, Result, anyhow};
use hickory_resolver::{
    TokioResolver,
    config::{LookupIpStrategy, NameServerConfig, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
};
use reqwest::{
    Client, ClientBuilder, NoProxy, Proxy,
    dns::{Addrs, Name, Resolve, Resolving},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::{Arc, LazyLock, RwLock},
};
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use sysproxy::Sysproxy;
use url::Url;

pub const DOH_CONFIG_STORAGE_KEY: &str = "network_doh_cfg";

const ALIDNS_DOH_URL: &str = "https://dns.alidns.com/dns-query";
const DNSPOD_DOH_URL: &str = "https://doh.pub/dns-query";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DohProvider {
    Alidns,
    Dnspod,
    Custom,
}

impl Default for DohProvider {
    fn default() -> Self {
        Self::Alidns
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DohConfig {
    pub enabled: bool,
    #[serde(default)]
    pub provider: DohProvider,
    #[serde(default)]
    pub custom_url: String,
}

impl Default for DohConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: DohProvider::Alidns,
            custom_url: String::new(),
        }
    }
}

#[derive(Clone)]
struct DohDnsResolver {
    resolver: TokioResolver,
}

impl DohDnsResolver {
    fn new(config: &DohConfig) -> Result<Self> {
        let endpoint = config.endpoint_url()?;
        let resolver_config = build_resolver_config(&endpoint)?;
        let mut builder =
            TokioResolver::builder_with_config(resolver_config, TokioRuntimeProvider::default());
        builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;

        Ok(Self {
            resolver: builder.build()?,
        })
    }
}

impl Resolve for DohDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.resolver.clone();
        Box::pin(async move {
            let lookup = resolver.lookup_ip(name.as_str()).await?;
            let addrs: Vec<_> = lookup.iter().map(|ip| SocketAddr::new(ip, 0)).collect();
            let addrs: Addrs = Box::new(addrs.into_iter());
            Ok(addrs)
        })
    }
}

static CURRENT_DOH_CONFIG: LazyLock<RwLock<DohConfig>> =
    LazyLock::new(|| RwLock::new(DohConfig::default()));
static DEFAULT_CLIENT: LazyLock<RwLock<Client>> =
    LazyLock::new(|| RwLock::new(build_client_for_config(&DohConfig::default())));

impl DohConfig {
    fn normalized(mut self) -> Self {
        self.custom_url = self.custom_url.trim().to_string();
        self
    }

    fn endpoint_url(&self) -> Result<Url> {
        let url = match self.provider {
            DohProvider::Alidns => {
                Url::parse(ALIDNS_DOH_URL).expect("static AliDNS DoH URL is valid")
            }
            DohProvider::Dnspod => {
                Url::parse(DNSPOD_DOH_URL).expect("static DNSPod DoH URL is valid")
            }
            DohProvider::Custom => {
                Url::parse(self.custom_url.trim()).context("invalid custom DoH provider URL")?
            }
        };

        if url.scheme() != "https" {
            return Err(anyhow!("DoH provider URL must use https"));
        }
        if url.host_str().is_none() {
            return Err(anyhow!("DoH provider URL must contain a hostname"));
        }

        Ok(url)
    }
}

pub fn get_doh_config() -> DohConfig {
    CURRENT_DOH_CONFIG
        .read()
        .expect("DoH config lock poisoned")
        .clone()
}

pub fn set_doh_config(config: DohConfig) -> Result<()> {
    let normalized = config.normalized();
    if normalized.enabled && normalized.provider == DohProvider::Custom {
        normalized.endpoint_url()?;
    }

    {
        let mut guard = CURRENT_DOH_CONFIG
            .write()
            .expect("DoH config lock poisoned");
        *guard = normalized.clone();
    }

    let rebuilt_client = build_client_for_config(&normalized);
    let mut client_guard = DEFAULT_CLIENT
        .write()
        .expect("default client lock poisoned");
    *client_guard = rebuilt_client;

    Ok(())
}

pub fn default_client() -> Client {
    DEFAULT_CLIENT
        .read()
        .expect("default client lock poisoned")
        .clone()
}

pub fn default_client_builder() -> ClientBuilder {
    let config = get_doh_config();
    build_client_builder_for_config(&config)
}

fn build_client_for_config(config: &DohConfig) -> Client {
    build_client_builder_for_config(config)
        .build()
        .expect("failed to build default reqwest client")
}

fn build_client_builder_for_config(config: &DohConfig) -> ClientBuilder {
    let mut builder = Client::builder();

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        if let Ok(proxy) = Sysproxy::get_system_proxy() {
            if proxy.enable {
                if let Ok(proxy_builder) = Proxy::all(format!("{}:{}", proxy.host, proxy.port)) {
                    builder = builder
                        .danger_accept_invalid_certs(true)
                        .proxy(proxy_builder.no_proxy(NoProxy::from_string(proxy.bypass.as_str())));
                }
            }
        }
    }

    if !config.enabled {
        return builder;
    }

    match DohDnsResolver::new(config) {
        Ok(resolver) => builder.dns_resolver(resolver),
        Err(err) => {
            log::warn!(
                "[netcfg] failed to construct DoH resolver, fallback to system DNS: {:?}",
                err
            );
            builder
        }
    }
}

fn build_resolver_config(endpoint: &Url) -> Result<ResolverConfig> {
    let host = endpoint
        .host_str()
        .context("DoH endpoint missing host")?
        .to_string();
    let port = endpoint.port_or_known_default().unwrap_or(443);
    let endpoint_path = build_http_endpoint(endpoint);
    let ips = resolve_provider_ips(&host, port)?;

    let mut config = ResolverConfig::default();
    for ip in ips {
        let mut name_server = NameServerConfig::https(
            ip,
            Arc::<str>::from(host.clone()),
            Some(Arc::<str>::from(endpoint_path.clone())),
        );
        for connection in &mut name_server.connections {
            connection.port = port;
        }
        name_server.trust_negative_responses = true;
        config.add_name_server(name_server);
    }

    Ok(config)
}

fn build_http_endpoint(endpoint: &Url) -> String {
    let path = match endpoint.path() {
        "" | "/" => "/dns-query",
        other => other,
    };

    match endpoint.query() {
        Some(query) if !query.is_empty() => format!("{path}?{query}"),
        _ => path.to_string(),
    }
}

fn resolve_provider_ips(host: &str, port: u16) -> Result<Vec<IpAddr>> {
    let resolved = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve DoH provider host {host}"))?;

    let mut ips = BTreeSet::new();
    for addr in resolved {
        ips.insert(addr.ip());
    }

    if ips.is_empty() {
        return Err(anyhow!("DoH provider host {host} resolved to no IPs"));
    }

    Ok(ips.into_iter().collect())
}
