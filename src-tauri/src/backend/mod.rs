pub mod amnezia;
pub mod hysteria2;
pub mod openvpn;

use crate::{
    config::{AwgVersion, Profile},
    daemon,
};
use anyhow::{anyhow, Result};
use std::time::Duration;

#[allow(async_fn_in_trait)]
pub trait Tunnel {
    fn name(&self) -> &'static str;
    async fn up(&mut self) -> Result<()>;
    async fn wait(&mut self) -> Result<()>;
    async fn down(&mut self) -> Result<()>;
}

pub async fn run(profile: Profile) -> Result<()> {
    match profile {
        Profile::Hysteria2(c) => supervise(hysteria2::Hysteria2::new(c)).await,
        Profile::AmneziaWg(c) => supervise(amnezia::Amnezia::new(c, AwgVersion::V1)).await,
        Profile::AmneziaWg2(c) => supervise(amnezia::Amnezia::new(c, AwgVersion::V2)).await,
        Profile::OpenVpn(c) => supervise(openvpn::OpenVpn::new(c)).await,
    }
}

async fn shutdown_signal() {
    let stop = async {
        while !daemon::stop_requested() {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    };
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM");
        let mut int = signal(SignalKind::interrupt()).expect("SIGINT");
        tokio::select! { _ = term.recv() => {}, _ = int.recv() => {}, _ = stop => {} }
    }
    #[cfg(windows)]
    {
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = stop => {} }
    }
}

async fn supervise<T: Tunnel>(mut t: T) -> Result<()> {
    let name = t.name();
    daemon::set_state("connecting", &format!("Подключение: {name}"), None);
    if let Err(e) = t.up().await {
        let _ = t.down().await;
        return Err(e.context(format!("{name}: не удалось поднять туннель")));
    }
    daemon::set_state("up", name, None);
    tracing::info!("{name}: туннель поднят");

    let result = tokio::select! {
        _ = shutdown_signal() => Ok(()),
        r = t.wait() => r.and_then(|_| Err(anyhow!("{name}: туннель завершился неожиданно"))),
    };
    if let Err(e) = t.down().await {
        tracing::warn!("ошибка при остановке: {e:#}");
    }
    result
}
