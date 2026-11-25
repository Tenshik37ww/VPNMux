//! AmneziaWG 1.x / 2.0 через `awg-quick` (amneziawg-tools + amneziawg-go или модуль ядра).
//! Мы генерируем стандартный wg-quick-конфиг с дополнительными ключами обфускации
//! (Jc/Jmin/Jmax/S1..S4/H1..H4/I1..I5), а маршруты, DNS и MTU делает awg-quick.

use super::Tunnel;
use crate::{
    config::{AmneziaCfg, AwgVersion},
    components, util,
};
use anyhow::{bail, Context, Result};
use std::{fmt::{Display, Write}, path::{Path, PathBuf}, time::Duration};
use tokio::process::Child;

pub struct Amnezia {
    cfg: AmneziaCfg,
    ver: AwgVersion,
    conf_path: Option<PathBuf>,
    is_up: bool,
    mac: Option<MacTun>,
}

/// macOS: userspace-процесс amneziawg-go + изменения сети, которые нужно откатить.
struct MacTun {
    go: Child,
    dns: Vec<(String, Vec<String>)>,
    hosts: Vec<String>,
}

impl Amnezia {
    pub fn new(cfg: AmneziaCfg, ver: AwgVersion) -> Self {
        Self { cfg, ver, conf_path: None, is_up: false, mac: None }
    }

    fn render(&self) -> String {
        fn kv<T: Display>(s: &mut String, k: &str, v: &Option<T>) {
            if let Some(v) = v {
                let _ = writeln!(s, "{k} = {v}");
            }
        }
        let c = &self.cfg;
        let o = &c.obfuscation;
        let mut s = String::from("[Interface]\n");
        let _ = writeln!(s, "PrivateKey = {}", c.private_key);
        let _ = writeln!(s, "Address = {}", c.address.join(", "));
        if !c.dns.is_empty() {
            let _ = writeln!(s, "DNS = {}", c.dns.join(", "));
        }
        kv(&mut s, "MTU", &c.mtu);

        kv(&mut s, "Jc", &o.jc);
        kv(&mut s, "Jmin", &o.jmin);
        kv(&mut s, "Jmax", &o.jmax);
        kv(&mut s, "S1", &o.s1);
        kv(&mut s, "S2", &o.s2);
        if self.ver == AwgVersion::V2 {
            kv(&mut s, "S3", &o.s3);
            kv(&mut s, "S4", &o.s4);
        }
        kv(&mut s, "H1", &o.h1);
        kv(&mut s, "H2", &o.h2);
        kv(&mut s, "H3", &o.h3);
        kv(&mut s, "H4", &o.h4);
        if self.ver == AwgVersion::V2 {
            kv(&mut s, "I1", &o.i1);
            kv(&mut s, "I2", &o.i2);
            kv(&mut s, "I3", &o.i3);
            kv(&mut s, "I4", &o.i4);
            kv(&mut s, "I5", &o.i5);
        }

        let p = &c.peer;
        s.push_str("\n[Peer]\n");
        let _ = writeln!(s, "PublicKey = {}", p.public_key);
        kv(&mut s, "PresharedKey", &p.preshared_key);
        let _ = writeln!(s, "Endpoint = {}", p.endpoint);
        let _ = writeln!(s, "AllowedIPs = {}", p.allowed_ips.join(", "));
        kv(&mut s, "PersistentKeepalive", &p.persistent_keepalive);
        s
    }
}

impl Amnezia {
    /// Windows: amneziawg.exe (официальный сервис туннелей); Linux: awg-quick из PATH.
    async fn tool(&self) -> Result<PathBuf> {
        if cfg!(windows) {
            components::ensure("amneziawg").await
        } else {
            Ok(PathBuf::from(&self.cfg.quick_binary))
        }
    }

    /// Конфиг в формате `awg setconf` (без Address/DNS/MTU).
    fn render_wg(&self) -> String {
        self.render()
            .lines()
            .filter(|l| !["Address", "DNS", "MTU"].iter().any(|k| l.starts_with(k)))
            .map(|l| format!("{l}\n"))
            .collect()
    }

    /// macOS: amneziawg-go + `awg setconf` + ifconfig/route/networksetup
    /// (bash-версия awg-quick требует bash 4+, которого в macOS нет).
    async fn mac_up(&mut self) -> Result<()> {
        let main = components::ensure("amneziawg").await?;
        let dir = main.parent().map(|p| p.to_path_buf()).unwrap_or_default();
        let rt = util::runtime_dir()?;
        let name_file = rt.join("awg.name");
        let _ = std::fs::remove_file(&name_file);
        let wgconf = rt.join("awg-wg.conf");
        util::write_secret(&wgconf, &self.render_wg())?;

        let go = util::cmd(dir.join("amneziawg-go"))
            .args(["-f", "utun"])
            .env("WG_TUN_NAME_FILE", &name_file)
            .stdin(std::process::Stdio::null())
            .stdout(util::log_stdio())
            .stderr(util::log_stdio())
            .kill_on_drop(true)
            .spawn()
            .context("запуск amneziawg-go")?;
        self.mac = Some(MacTun { go, dns: vec![], hosts: vec![] });

        let mut ifname = String::new();
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if let Ok(t) = std::fs::read_to_string(&name_file) {
                if !t.trim().is_empty() {
                    ifname = t.trim().to_string();
                    break;
                }
            }
        }
        if ifname.is_empty() {
            bail!("amneziawg-go не создал интерфейс");
        }
        let ifn = ifname.as_str();
        util::run_in(&dir.join("awg"), &["setconf", ifn, &wgconf.to_string_lossy()], None, &[]).await?;

        for a in &self.cfg.address {
            let (ip, pfx) = a.split_once('/').unwrap_or((a.as_str(), if a.contains(':') { "128" } else { "32" }));
            if ip.contains(':') {
                util::run_checked("ifconfig", &[ifn, "inet6", ip, "prefixlen", pfx, "alias"]).await?;
            } else {
                util::run_checked("ifconfig", &[ifn, "inet", ip, ip, "alias"]).await?;
            }
        }
        let mtu = self.cfg.mtu.unwrap_or(1380).to_string();
        util::run_checked("ifconfig", &[ifn, "mtu", &mtu, "up"]).await?;

        // маршрут до самого сервера — мимо туннеля
        let gw = util::output("route", &["-n", "get", "default"]).await.ok().and_then(|o| {
            o.lines().find_map(|l| l.trim().strip_prefix("gateway:").map(|g| g.trim().to_string()))
        });
        let host = self.cfg.peer.endpoint.rsplit_once(':').map(|(h, _)| h).unwrap_or("").trim_matches(|c| c == '[' || c == ']').to_string();
        if let Some(gw) = gw {
            if let Ok(addrs) = tokio::net::lookup_host((host.as_str(), 0)).await {
                for ip in addrs.map(|a| a.ip()).filter(|i| i.is_ipv4()) {
                    let s = ip.to_string();
                    if util::run_checked("route", &["-q", "-n", "add", "-inet", &s, "-gateway", &gw]).await.is_ok() {
                        self.mac.as_mut().unwrap().hosts.push(s);
                    }
                }
            }
        }
        for c in &self.cfg.peer.allowed_ips {
            let fam = if c.contains(':') { "-inet6" } else { "-inet" };
            let list: Vec<&str> = match c.as_str() {
                "0.0.0.0/0" => vec!["0.0.0.0/1", "128.0.0.0/1"],
                "::/0" => vec!["::/1", "8000::/1"],
                _ => vec![c.as_str()],
            };
            for r in list {
                util::run_checked("route", &["-q", "-n", "add", fam, r, "-interface", ifn]).await?;
            }
        }
        if !self.cfg.dns.is_empty() {
            let svcs = util::output("networksetup", &["-listallnetworkservices"]).await?;
            for s in svcs.lines().skip(1).map(str::trim).filter(|s| !s.is_empty() && !s.starts_with('*')) {
                let cur = util::output("networksetup", &["-getdnsservers", s]).await.unwrap_or_default();
                let old: Vec<String> = if cur.contains("aren't any") { vec![] } else { cur.split_whitespace().map(String::from).collect() };
                let mut args = vec!["-setdnsservers", s];
                args.extend(self.cfg.dns.iter().map(|d| d.as_str()));
                if util::run_checked("networksetup", &args).await.is_ok() {
                    self.mac.as_mut().unwrap().dns.push((s.to_string(), old));
                }
            }
        }
        Ok(())
    }

    async fn mac_down(&mut self) {
        if let Some(mut m) = self.mac.take() {
            for (svc, old) in &m.dns {
                let mut a = vec!["-setdnsservers", svc.as_str()];
                if old.is_empty() {
                    a.push("Empty");
                } else {
                    a.extend(old.iter().map(|s| s.as_str()));
                }
                let _ = util::run_checked("networksetup", &a).await;
            }
            for h in &m.hosts {
                let _ = util::run_checked("route", &["-q", "-n", "delete", "-inet", h]).await;
            }
            util::terminate(&mut m.go, Duration::from_secs(5)).await;
        }
    }
}

impl Tunnel for Amnezia {
    fn name(&self) -> &'static str {
        match self.ver {
            AwgVersion::V1 => "AmneziaWG 1.x",
            AwgVersion::V2 => "AmneziaWG 2.0",
        }
    }

    async fn up(&mut self) -> Result<()> {
        let path = util::runtime_dir()?.join(format!("{}.conf", self.cfg.interface));
        util::write_secret(&path, &self.render())?;
        self.conf_path = Some(path.clone());
        let p = path.to_string_lossy().into_owned();
        if cfg!(target_os = "macos") {
            self.mac_up().await?;
        } else if cfg!(windows) {
            let t = self.tool().await?;
            util::run_in(&t, &["/installtunnelservice", &p], None, &[]).await?;
        } else {
            let t = self.tool().await?;
            util::run_in(&t, &["up", &p], None, &[("WG_QUICK_USERSPACE_IMPLEMENTATION", "amneziawg-go")]).await?;
        }
        self.is_up = true;
        Ok(())
    }

    async fn wait(&mut self) -> Result<()> {
        if let Some(m) = self.mac.as_mut() {
            let st = m.go.wait().await?;
            bail!("amneziawg-go завершился: {st}");
        }
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let ok = if cfg!(windows) {
                let svc = format!("AmneziaWGTunnel${}", self.cfg.interface);
                util::output("sc", &["query", &svc]).await.map(|o| o.contains("RUNNING")).unwrap_or(false)
            } else {
                util::output(&self.cfg.awg_binary, &["show", &self.cfg.interface]).await.is_ok()
            };
            if !ok {
                bail!("интерфейс {} исчез", self.cfg.interface);
            }
        }
    }

    async fn down(&mut self) -> Result<()> {
        self.mac_down().await;
        let Some(path) = self.conf_path.take() else { return Ok(()) };
        let mut res = Ok(());
        if self.is_up && !cfg!(target_os = "macos") {
            let p = path.to_string_lossy().into_owned();
            res = if cfg!(windows) {
                match self.tool().await {
                    Ok(t) => util::run_in(&t, &["/uninstalltunnelservice", &self.cfg.interface], None, &[]).await,
                    Err(e) => Err(e),
                }
            } else {
                util::run_in(Path::new(&self.cfg.quick_binary), &["down", &p], None, &[("WG_QUICK_USERSPACE_IMPLEMENTATION", "amneziawg-go")]).await
            };
        }
        self.is_up = false;
        let _ = std::fs::remove_file(path);
        res
    }
}
