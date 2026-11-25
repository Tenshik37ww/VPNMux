use crate::util::check_plain;
use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::{
    fmt,
    path::{Path, PathBuf},
};

// ───────────────────────── Профиль ─────────────────────────

#[derive(Debug, Deserialize)]
#[serde(tag = "protocol")]
pub enum Profile {
    #[serde(rename = "hysteria2")]
    Hysteria2(Hysteria2Cfg),
    #[serde(rename = "amneziawg")]
    AmneziaWg(AmneziaCfg),
    #[serde(rename = "amneziawg2")]
    AmneziaWg2(AmneziaCfg),
    #[serde(rename = "openvpn")]
    OpenVpn(OpenVpnCfg),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AwgVersion {
    V1,
    V2,
}

impl Profile {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("чтение профиля {}", path.display()))?;
        let p: Profile =
            toml::from_str(&text).with_context(|| format!("разбор профиля {}", path.display()))?;
        p.validate()?;
        Ok(p)
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Profile::Hysteria2(c) => c.validate(),
            Profile::AmneziaWg(c) => c.validate(AwgVersion::V1),
            Profile::AmneziaWg2(c) => c.validate(AwgVersion::V2),
            Profile::OpenVpn(c) => c.validate(),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Profile::Hysteria2(_) => "Hysteria2",
            Profile::AmneziaWg(_) => "AmneziaWG 1.x",
            Profile::AmneziaWg2(_) => "AmneziaWG 2.0",
            Profile::OpenVpn(_) => "OpenVPN",
        }
    }
}

// ───────────────────────── Hysteria2 ─────────────────────────

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Hy2Mode {
    /// Системный VPN через TUN (весь трафик)
    #[default]
    Tun,
    /// Локальный SOCKS5-прокси
    Socks5,
}

#[derive(Debug, Deserialize)]
pub struct Hysteria2Cfg {
    /// "host:port" (можно диапазон портов: "host:20000-30000")
    pub server: String,
    pub password: String,
    pub sni: Option<String>,
    #[serde(default)]
    pub insecure: bool,
    /// Пиннинг сертификата: SHA-256 отпечаток ("AA:BB:..." или hex)
    pub pin_sha256: Option<String>,
    /// Пароль обфускации Salamander
    pub obfs_password: Option<String>,
    pub up_mbps: Option<u32>,
    pub down_mbps: Option<u32>,
    #[serde(default)]
    pub mode: Hy2Mode,
    #[serde(default = "d_hy2_tun")]
    pub tun_name: String,
    #[serde(default = "d_socks")]
    pub socks5_listen: String,
    #[serde(default = "d_hy2_bin")]
    pub binary: String,
}

impl Hysteria2Cfg {
    fn validate(&self) -> Result<()> {
        if !self.server.contains(':') {
            bail!("hysteria2: `server` должен быть в формате host:port");
        }
        if self.password.is_empty() {
            bail!("hysteria2: `password` не должен быть пустым");
        }
        if self.tun_name.len() > 15 {
            bail!("hysteria2: `tun_name` длиннее 15 символов");
        }
        for (n, v) in [("server", &self.server), ("password", &self.password)] {
            check_plain(n, v)?;
        }
        Ok(())
    }
}

// ───────────────────────── OpenVPN ─────────────────────────

#[derive(Debug, Deserialize)]
pub struct OpenVpnCfg {
    /// Путь к .ovpn
    pub config: PathBuf,
    pub username: Option<String>,
    pub password: Option<String>,
    /// Дополнительные аргументы, напр. ["--up", "/etc/openvpn/update-resolv-conf"]
    #[serde(default)]
    pub extra_args: Vec<String>,
    #[serde(default = "d_ovpn_bin")]
    pub binary: String,
    #[serde(default = "d_timeout")]
    pub connect_timeout_secs: u64,
}

impl OpenVpnCfg {
    fn validate(&self) -> Result<()> {
        if !self.config.is_file() {
            bail!("openvpn: файл конфигурации {} не найден", self.config.display());
        }
        match (&self.username, &self.password) {
            (Some(u), Some(p)) => {
                check_plain("username", u)?;
                check_plain("password", p)?;
            }
            (None, None) => {}
            _ => bail!("openvpn: укажите `username` и `password` вместе (или ни одного)"),
        }
        Ok(())
    }
}

// ───────────────────────── AmneziaWG ─────────────────────────

#[derive(Debug, Deserialize)]
pub struct Peer {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub endpoint: String,
    #[serde(default = "d_allowed")]
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: Option<u16>,
}

/// Значение H1..H4: число (v1) либо диапазон "lo-hi" (v2).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum HValue {
    Num(u32),
    Range(String),
}

impl HValue {
    pub fn bounds(&self) -> Result<(u32, u32)> {
        match self {
            HValue::Num(n) => Ok((*n, *n)),
            HValue::Range(s) => {
                let (a, b) = s
                    .split_once('-')
                    .ok_or_else(|| anyhow!("некорректный диапазон `{s}` (ожидается lo-hi)"))?;
                let (a, b): (u32, u32) = (a.trim().parse()?, b.trim().parse()?);
                if a > b {
                    bail!("диапазон `{s}`: начало больше конца");
                }
                Ok((a, b))
            }
        }
    }
}

impl fmt::Display for HValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HValue::Num(n) => write!(f, "{n}"),
            HValue::Range(s) => write!(f, "{s}"),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct Obfuscation {
    // v1 + v2
    pub jc: Option<u16>,
    pub jmin: Option<u16>,
    pub jmax: Option<u16>,
    pub s1: Option<u16>,
    pub s2: Option<u16>,
    pub h1: Option<HValue>,
    pub h2: Option<HValue>,
    pub h3: Option<HValue>,
    pub h4: Option<HValue>,
    // только v2
    pub s3: Option<u16>,
    pub s4: Option<u16>,
    pub i1: Option<String>,
    pub i2: Option<String>,
    pub i3: Option<String>,
    pub i4: Option<String>,
    pub i5: Option<String>,
}

impl Obfuscation {
    pub fn h_all(&self) -> [(&'static str, &Option<HValue>); 4] {
        [("h1", &self.h1), ("h2", &self.h2), ("h3", &self.h3), ("h4", &self.h4)]
    }
    pub fn i_all(&self) -> [(&'static str, &Option<String>); 5] {
        [("i1", &self.i1), ("i2", &self.i2), ("i3", &self.i3), ("i4", &self.i4), ("i5", &self.i5)]
    }
}

#[derive(Debug, Deserialize)]
pub struct AmneziaCfg {
    #[serde(default = "d_awg_if")]
    pub interface: String,
    pub private_key: String,
    pub address: Vec<String>,
    #[serde(default)]
    pub dns: Vec<String>,
    pub mtu: Option<u16>,
    pub peer: Peer,
    #[serde(default)]
    pub obfuscation: Obfuscation,
    #[serde(default = "d_awg_quick")]
    pub quick_binary: String,
    #[serde(default = "d_awg")]
    pub awg_binary: String,
}

fn check_wg_key(name: &str, k: &str) -> Result<()> {
    if k.len() != 44 || !k.ends_with('=') {
        bail!("`{name}` не похож на ключ WireGuard (ожидается base64, 44 символа)");
    }
    check_plain(name, k)
}

impl AmneziaCfg {
    pub fn validate(&self, ver: AwgVersion) -> Result<()> {
        let tag = if ver == AwgVersion::V1 { "amneziawg" } else { "amneziawg2" };

        if self.interface.is_empty()
            || self.interface.len() > 15
            || !self.interface.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            bail!("{tag}: некорректное имя интерфейса `{}`", self.interface);
        }
        check_wg_key("private_key", &self.private_key)?;
        check_wg_key("peer.public_key", &self.peer.public_key)?;
        if let Some(k) = &self.peer.preshared_key {
            check_wg_key("peer.preshared_key", k)?;
        }
        if self.address.is_empty() {
            bail!("{tag}: `address` не задан");
        }
        for v in self.address.iter().chain(&self.dns).chain(&self.peer.allowed_ips) {
            check_plain("address/dns/allowed_ips", v)?;
        }
        check_plain("peer.endpoint", &self.peer.endpoint)?;
        if !self.peer.endpoint.contains(':') {
            bail!("{tag}: `peer.endpoint` должен быть host:port");
        }

        let o = &self.obfuscation;
        for (n, v) in o.i_all() {
            if let Some(s) = v {
                check_plain(n, s)?;
                if s.trim().is_empty() {
                    bail!("{tag}: `{n}` пустой");
                }
            }
        }

        match ver {
            AwgVersion::V1 => self.validate_v1(),
            AwgVersion::V2 => self.validate_v2(),
        }
    }

    fn validate_v1(&self) -> Result<()> {
        let o = &self.obfuscation;
        let req = |v: Option<u16>, n: &str| {
            v.ok_or_else(|| anyhow!("amneziawg: параметр obfuscation.{n} обязателен"))
        };
        let jc = req(o.jc, "jc")?;
        let jmin = req(o.jmin, "jmin")?;
        let jmax = req(o.jmax, "jmax")?;
        let s1 = req(o.s1, "s1")?;
        let s2 = req(o.s2, "s2")?;

        if !(1..=128).contains(&jc) {
            bail!("amneziawg: jc должен быть в диапазоне 1..=128 (рекомендуется 4–12)");
        }
        if jmin > jmax || jmax > 1280 {
            bail!("amneziawg: требуется jmin <= jmax <= 1280");
        }
        if s1 > 1132 || s2 > 1188 {
            bail!("amneziawg: s1 <= 1132 и s2 <= 1188");
        }
        if s1 + 56 == s2 {
            bail!("amneziawg: s1 + 56 не должно равняться s2");
        }
        if o.s3.is_some() || o.s4.is_some() || o.i_all().iter().any(|(_, v)| v.is_some()) {
            bail!("amneziawg: s3/s4/i1..i5 относятся к AmneziaWG 2.0 — используйте protocol = \"amneziawg2\"");
        }

        let mut seen = Vec::new();
        for (n, h) in o.h_all() {
            let h = h.as_ref().ok_or_else(|| anyhow!("amneziawg: obfuscation.{n} обязателен"))?;
            let HValue::Num(v) = h else {
                bail!("amneziawg: {n} должен быть числом (диапазоны — только в amneziawg2)");
            };
            if *v < 5 {
                bail!("amneziawg: {n} должен быть >= 5 (1–4 заняты стандартным WireGuard)");
            }
            if seen.contains(v) {
                bail!("amneziawg: значения h1..h4 должны быть уникальны");
            }
            seen.push(*v);
        }
        Ok(())
    }

    fn validate_v2(&self) -> Result<()> {
        let o = &self.obfuscation;
        if let (Some(jmin), Some(jmax)) = (o.jmin, o.jmax) {
            if jmin > jmax {
                bail!("amneziawg2: jmin не должен превышать jmax");
            }
        }
        if let (Some(s1), Some(s2)) = (o.s1, o.s2) {
            if s1 + 56 == s2 {
                bail!("amneziawg2: s1 + 56 не должно равняться s2");
            }
        }
        // H1..H4: числа или диапазоны, >= 5, без пересечений
        let mut ranges: Vec<(u32, u32, &str)> = Vec::new();
        for (n, h) in o.h_all() {
            if let Some(h) = h {
                let (lo, hi) = h.bounds().with_context(|| format!("amneziawg2: {n}"))?;
                if lo < 5 {
                    bail!("amneziawg2: {n} должен быть >= 5");
                }
                ranges.push((lo, hi, n));
            }
        }
        ranges.sort();
        for w in ranges.windows(2) {
            if w[0].1 >= w[1].0 {
                bail!("amneziawg2: диапазоны {} и {} пересекаются", w[0].2, w[1].2);
            }
        }
        Ok(())
    }
}

// ───────────────────────── defaults ─────────────────────────

fn d_hy2_tun() -> String { "hy2tun".into() }
fn d_socks() -> String { "127.0.0.1:1080".into() }
fn d_hy2_bin() -> String { "hysteria".into() }
fn d_ovpn_bin() -> String { "openvpn".into() }
fn d_timeout() -> u64 { 60 }
fn d_allowed() -> Vec<String> { vec!["0.0.0.0/0".into(), "::/0".into()] }
fn d_awg_if() -> String { "awg0".into() }
fn d_awg_quick() -> String { "awg-quick".into() }
fn d_awg() -> String { "awg".into() }

// ───────────── для GUI ─────────────
impl Profile {
    pub fn parse(text: &str) -> Result<Self> {
        let p: Profile = toml::from_str(text).context("разбор профиля")?;
        p.validate()?;
        Ok(p)
    }

    pub fn protocol_id(&self) -> &'static str {
        match self {
            Profile::Hysteria2(_) => "hysteria2",
            Profile::AmneziaWg(_) => "amneziawg",
            Profile::AmneziaWg2(_) => "amneziawg2",
            Profile::OpenVpn(_) => "openvpn",
        }
    }

    /// "host:port" сервера (для геолокации и отображения)
    pub fn endpoint(&self) -> String {
        match self {
            Profile::Hysteria2(c) => c.server.clone(),
            Profile::AmneziaWg(c) | Profile::AmneziaWg2(c) => c.peer.endpoint.clone(),
            Profile::OpenVpn(c) => std::fs::read_to_string(&c.config)
                .ok()
                .and_then(|t| {
                    t.lines().find_map(|l| {
                        let mut it = l.split_whitespace();
                        (it.next() == Some("remote")).then(|| {
                            let h = it.next().unwrap_or("").to_string();
                            format!("{h}:{}", it.next().unwrap_or("1194"))
                        })
                    })
                })
                .unwrap_or_default(),
        }
    }
}
