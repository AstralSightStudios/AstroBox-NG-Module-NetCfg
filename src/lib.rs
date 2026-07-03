use anyhow::{Context, Result, anyhow};
use hickory_resolver::{
    TokioResolver,
    config::{LookupIpStrategy, NameServerConfig, ResolverConfig},
    name_server::TokioConnectionProvider,
    proto::xfer::Protocol,
};
use reqwest::{
    Client, ClientBuilder, NoProxy, Proxy,
    dns::{Addrs, Name, Resolve, Resolving},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::{LazyLock, RwLock},
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
            TokioResolver::builder_with_config(resolver_config, TokioConnectionProvider::default());
        builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;

        Ok(Self {
            resolver: builder.build(),
        })
    }
}

impl Resolve for DohDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.resolver.clone();
        Box::pin(async move {
            let lookup = resolver.lookup_ip(name.as_str()).await?;
            let addrs: Addrs = Box::new(lookup.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

/// 判断主机名是否属于 GitHub 及其资源域（含 `raw.githubusercontent.com`、release 下载所用的
/// `objects.githubusercontent.com`、`codeload.github.com` 等）。
pub fn is_github_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "github.com"
        || host == "githubusercontent.com"
        || host.ends_with(".github.com")
        || host.ends_with(".githubusercontent.com")
}

/// 固定使用阿里 DoH 解析 GitHub 域名的配置（独立于用户的全局 DoH 开关）。
fn github_doh_source_config() -> DohConfig {
    DohConfig {
        enabled: true,
        provider: DohProvider::Alidns,
        custom_url: String::new(),
    }
}

/// 仅对 GitHub 域名走 DoH、其余域名走系统解析的解析器。
///
/// 用于「GitHub DoH」CDN：即使全局 DoH 关闭，也让 GitHub 请求绕过被污染的本地 DNS。
#[derive(Clone)]
struct GithubDohResolver {
    doh: Option<DohDnsResolver>,
}

impl GithubDohResolver {
    fn new() -> Self {
        let doh = match DohDnsResolver::new(&github_doh_source_config()) {
            Ok(resolver) => Some(resolver),
            Err(err) => {
                log::warn!(
                    "[netcfg] failed to build GitHub DoH resolver, GitHub will use system DNS: {:?}",
                    err
                );
                None
            }
        };
        Self { doh }
    }
}

fn system_resolve(host: String) -> Resolving {
    Box::pin(async move {
        let addrs = tokio::task::spawn_blocking(move || {
            (host.as_str(), 0u16)
                .to_socket_addrs()
                .map(|iter| iter.collect::<Vec<_>>())
        })
        .await
        .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send + Sync>)?
        .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send + Sync>)?;
        let addrs: Addrs = Box::new(addrs.into_iter());
        Ok(addrs)
    })
}

impl Resolve for GithubDohResolver {
    fn resolve(&self, name: Name) -> Resolving {
        if is_github_host(name.as_str()) {
            if let Some(doh) = &self.doh {
                return doh.resolve(name);
            }
        }
        system_resolve(name.as_str().to_string())
    }
}

static CURRENT_DOH_CONFIG: LazyLock<RwLock<DohConfig>> =
    LazyLock::new(|| RwLock::new(DohConfig::default()));
static GITHUB_DOH_ENABLED: LazyLock<RwLock<bool>> = LazyLock::new(|| RwLock::new(false));
static DEFAULT_CLIENT: LazyLock<RwLock<Client>> =
    LazyLock::new(|| RwLock::new(build_client_for_config(&DohConfig::default(), false)));

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

    rebuild_default_client();
    Ok(())
}

pub fn get_github_doh() -> bool {
    *GITHUB_DOH_ENABLED
        .read()
        .expect("GitHub DoH flag lock poisoned")
}

/// 开关「GitHub DoH」加速：开启后无论全局 DoH 是否启用，默认客户端都会对 GitHub 域名走 DoH 解析。
pub fn set_github_doh(enabled: bool) {
    {
        let mut guard = GITHUB_DOH_ENABLED
            .write()
            .expect("GitHub DoH flag lock poisoned");
        if *guard == enabled {
            return;
        }
        *guard = enabled;
    }
    rebuild_default_client();
}

fn rebuild_default_client() {
    let config = get_doh_config();
    let github_doh = get_github_doh();
    let rebuilt = build_client_for_config(&config, github_doh);
    let mut client_guard = DEFAULT_CLIENT
        .write()
        .expect("default client lock poisoned");
    *client_guard = rebuilt;
}

pub fn default_client() -> Client {
    DEFAULT_CLIENT
        .read()
        .expect("default client lock poisoned")
        .clone()
}

pub fn default_client_builder() -> ClientBuilder {
    let config = get_doh_config();
    build_client_builder_for_config(&config, get_github_doh())
}

/// 始终对 GitHub 域名走 DoH 的独立客户端构造器（用于对「GitHub DoH」选项单独测速，不受全局开关影响）。
pub fn github_doh_client_builder() -> ClientBuilder {
    build_client_builder_for_config(&DohConfig::default(), true)
}

/// 始终对 GitHub 域名走 DoH 的独立客户端。
pub fn github_doh_client() -> Client {
    github_doh_client_builder()
        .build()
        .expect("failed to build GitHub DoH client")
}

fn build_client_for_config(config: &DohConfig, github_doh: bool) -> Client {
    build_client_builder_for_config(config, github_doh)
        .build()
        .expect("failed to build default reqwest client")
}

fn build_client_builder_for_config(config: &DohConfig, github_doh: bool) -> ClientBuilder {
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

    // 全局 DoH 优先：开启时所有域名走 DoH（GitHub 自然覆盖）。
    if config.enabled {
        match DohDnsResolver::new(config) {
            Ok(resolver) => return builder.dns_resolver2(resolver),
            Err(err) => {
                log::warn!(
                    "[netcfg] failed to construct DoH resolver, fallback to system DNS: {:?}",
                    err
                );
                return builder;
            }
        }
    }

    // 仅 GitHub DoH：GitHub 域名走 DoH，其余走系统解析。
    if github_doh {
        return builder.dns_resolver2(GithubDohResolver::new());
    }

    builder
}

fn build_resolver_config(endpoint: &Url) -> Result<ResolverConfig> {
    let host = endpoint
        .host_str()
        .context("DoH endpoint missing host")?
        .to_string();
    let port = endpoint.port_or_known_default().unwrap_or(443);
    let endpoint_path = build_http_endpoint(endpoint);
    let ips = resolve_provider_ips(&host, port)?;

    let mut config = ResolverConfig::new();
    for ip in ips {
        let mut name_server = NameServerConfig::new(SocketAddr::new(ip, port), Protocol::Https);
        name_server.tls_dns_name = Some(host.clone());
        name_server.http_endpoint = Some(endpoint_path.clone());
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
