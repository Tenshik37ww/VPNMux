//! OpenVPN через системный `openvpn`. Готовность определяем по строке
//! "Initialization Sequence Completed" в stdout.

use super::Tunnel;
use crate::{config::OpenVpnCfg, util};
use anyhow::{anyhow, bail, Context, Result};
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Child,
    sync::oneshot,
};

pub struct OpenVpn {
    cfg: OpenVpnCfg,
    child: Option<Child>,
    auth_path: Option<PathBuf>,
}

impl OpenVpn {
    pub fn new(cfg: OpenVpnCfg) -> Self {
        Self { cfg, child: None, auth_path: None }
    }
}

impl Tunnel for OpenVpn {
    fn name(&self) -> &'static str {
        "OpenVPN"
    }

    async fn up(&mut self) -> Result<()> {
        let bin = resolve_openvpn(&self.cfg.binary).await?;
        let mut cmd = util::cmd(&bin);
        cmd.arg("--config").arg(&self.cfg.config);

        if let (Some(u), Some(p)) = (&self.cfg.username, &self.cfg.password) {
            let path = util::runtime_dir()?.join("openvpn.auth");
            util::write_secret(&path, &format!("{u}\n{p}\n"))?;
            cmd.arg("--auth-user-pass").arg(&path).arg("--auth-nocache");
            self.auth_path = Some(path);
        }
        cmd.args(&self.cfg.extra_args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(util::log_stdio())
            .kill_on_drop(true);

        let mut child = cmd
            .spawn()
            .with_context(|| format!("не удалось запустить `{}`", self.cfg.binary))?;
        let stdout = child.stdout.take().expect("stdout piped");
        self.child = Some(child);

        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let mut tx = Some(tx);
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                tracing::info!("[openvpn] {line}");
                if line.contains("Initialization Sequence Completed") {
                    if let Some(t) = tx.take() {
                        let _ = t.send(());
                    }
                }
            }
        });

        let child = self.child.as_mut().unwrap();
        tokio::select! {
            r = tokio::time::timeout(Duration::from_secs(self.cfg.connect_timeout_secs), rx) => {
                match r {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(_)) => bail!("openvpn завершился до установления соединения"),
                    Err(_) => bail!("таймаут подключения ({} c)", self.cfg.connect_timeout_secs),
                }
            }
            st = child.wait() => bail!("openvpn завершился: {}", st?),
        }
    }

    async fn wait(&mut self) -> Result<()> {
        let child = self.child.as_mut().ok_or_else(|| anyhow!("процесс не запущен"))?;
        let st = child.wait().await?;
        bail!("openvpn завершился: {st}")
    }

    async fn down(&mut self) -> Result<()> {
        if let Some(mut c) = self.child.take() {
            util::terminate(&mut c, Duration::from_secs(8)).await;
        }
        if let Some(p) = self.auth_path.take() {
            let _ = std::fs::remove_file(p);
        }
        Ok(())
    }
}

async fn resolve_openvpn(cfg: &str) -> Result<PathBuf> {
    if cfg != "openvpn" {
        return Ok(PathBuf::from(cfg));
    }
    if cfg!(windows) {
        return crate::components::ensure("openvpn").await; // MSI с драйвером
    }
    if cfg!(target_os = "macos") {
        for p in [
            "/opt/homebrew/sbin/openvpn",
            "/usr/local/sbin/openvpn",
            "/opt/homebrew/bin/openvpn",
            "/usr/local/bin/openvpn",
        ] {
            if std::path::Path::new(p).exists() {
                return Ok(PathBuf::from(p));
            }
        }
        bail!("OpenVPN не найден: установите его командой `brew install openvpn`");
    }
    Ok(PathBuf::from(cfg))
}
