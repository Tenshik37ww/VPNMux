//! Hysteria2 через официальный клиент `hysteria` (apernet/hysteria v2.x).
//! Генерируем YAML-конфиг; в режиме TUN исключаем IP сервера из маршрутов,
//! чтобы не получить петлю.

use super::Tunnel;
use crate::{
    config::{Hy2Mode, Hysteria2Cfg},
    util,
};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Map, Value};
use std::{net::IpAddr, path::PathBuf, process::Stdio, time::Duration};
use tokio::process::Child;

pub struct Hysteria2 {
    cfg: Hysteria2Cfg,
    child: Option<Child>,
    conf_path: Option<PathBuf>,
}

impl Hysteria2 {
    pub fn new(cfg: Hysteria2Cfg) -> Self {
        Self { cfg, child: None, conf_path: None }
    }

    async fn resolve_server(&self) -> Result<Vec<IpAddr>> {
        let host = self
            .cfg
            .server
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(&self.cfg.server)
            .trim_matches(|c| c == '[' || c == ']')
            .to_string();
        let ips: Vec<IpAddr> = tokio::net::lookup_host((host.as_str(), 0))
            .await
            .with_context(|| format!("DNS-разрешение {host}"))?
            .map(|a| a.ip())
            .collect();
        if ips.is_empty() {
            bail!("не удалось получить IP сервера {host}");
        }
        Ok(ips)
    }

    async fn build_config(&self) -> Result<Value> {
        let c = &self.cfg;
        let mut root = json!({ "server": c.server, "auth": c.password });

        let mut tls = Map::new();
        if let Some(s) = &c.sni {
            tls.insert("sni".into(), json!(s));
        }
        if c.insecure {
            tls.insert("insecure".into(), json!(true));
        }
        if let Some(p) = &c.pin_sha256 {
            tls.insert("pinSHA256".into(), json!(p));
        }
        if !tls.is_empty() {
            root["tls"] = Value::Object(tls);
        }

        if let Some(p) = &c.obfs_password {
            root["obfs"] = json!({ "type": "salamander", "salamander": { "password": p } });
        }

        if c.up_mbps.is_some() || c.down_mbps.is_some() {
            let mut bw = Map::new();
            if let Some(u) = c.up_mbps {
                bw.insert("up".into(), json!(format!("{u} mbps")));
            }
            if let Some(d) = c.down_mbps {
                bw.insert("down".into(), json!(format!("{d} mbps")));
            }
            root["bandwidth"] = Value::Object(bw);
        }

        match c.mode {
            Hy2Mode::Socks5 => {
                root["socks5"] = json!({ "listen": c.socks5_listen });
            }
            Hy2Mode::Tun => {
                let ips = self.resolve_server().await?;
                let v4: Vec<String> =
                    ips.iter().filter(|i| i.is_ipv4()).map(|i| format!("{i}/32")).collect();
                let v6: Vec<String> =
                    ips.iter().filter(|i| i.is_ipv6()).map(|i| format!("{i}/128")).collect();
                let mut route = json!({ "ipv4": ["0.0.0.0/0"], "ipv6": ["::/0"] });
                if !v4.is_empty() {
                    route["ipv4Exclude"] = json!(v4);
                }
                if !v6.is_empty() {
                    route["ipv6Exclude"] = json!(v6);
                }
                root["tun"] = json!({
                    "name": c.tun_name,
                    "mtu": 1500,
                    "timeout": "5m",
                    "address": { "ipv4": "100.100.100.101/30", "ipv6": "2001::ff03/126" },
                    "route": route,
                });
            }
        }
        Ok(root)
    }
}

impl Tunnel for Hysteria2 {
    fn name(&self) -> &'static str {
        "Hysteria2"
    }

    async fn up(&mut self) -> Result<()> {
        let conf = self.build_config().await?;
        let path = util::runtime_dir()?.join("hysteria2.yaml");
        util::write_secret(&path, &serde_yaml::to_string(&conf)?)?;
        self.conf_path = Some(path.clone());

        let bin = if self.cfg.binary == "hysteria" {
            resolve_hysteria().await?
        } else {
            PathBuf::from(&self.cfg.binary)
        };
        let child = util::cmd(&bin)
            .args(["client", "-c"])
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(util::log_stdio())
            .stderr(util::log_stdio())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("не удалось запустить `{}`", self.cfg.binary))?;
        self.child = Some(child);

        // Если клиент упал сразу (плохой конфиг, нет прав на TUN) — скажем об этом сразу.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        if let Some(st) = self.child.as_mut().unwrap().try_wait()? {
            self.child = None;
            bail!("hysteria завершился сразу после запуска: {st}");
        }
        Ok(())
    }

    async fn wait(&mut self) -> Result<()> {
        let child = self.child.as_mut().ok_or_else(|| anyhow!("процесс не запущен"))?;
        let st = child.wait().await?;
        bail!("hysteria завершился: {st}")
    }

    async fn down(&mut self) -> Result<()> {
        if let Some(mut c) = self.child.take() {
            util::terminate(&mut c, Duration::from_secs(5)).await;
        }
        if let Some(p) = self.conf_path.take() {
            let _ = std::fs::remove_file(p);
        }
        Ok(())
    }
}

/// Hysteria (скачивается автоматически) + wintun.dll рядом с ним на Windows.
async fn resolve_hysteria() -> Result<PathBuf> {
    let bin = crate::components::ensure("hysteria").await?;
    #[cfg(windows)]
    {
        let dll = crate::components::ensure("wintun").await?;
        let dst = bin.with_file_name("wintun.dll");
        if !dst.exists() {
            std::fs::copy(&dll, &dst)?;
        }
    }
    Ok(bin)
}
