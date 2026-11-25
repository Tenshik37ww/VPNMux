//! Headless-режим: `vpnmux-app --core <profile.toml> --stop <файл> --id <id>`.
//! Запускается с правами администратора/root, поднимает туннель, публикует состояние
//! в state.json (его читает GUI) и останавливается, когда появляется stop-файл.

use crate::{backend, config::Profile, util};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct StateData {
    pub phase: String,
    pub message: String,
    pub progress: Option<u8>,
    pub since: u64,
    pub id: String,
    pub ts: u64,
}

static STATE: Mutex<StateData> = Mutex::new(StateData {
    phase: String::new(),
    message: String::new(),
    progress: None,
    since: 0,
    id: String::new(),
    ts: 0,
});
static STOP: OnceLock<PathBuf> = OnceLock::new();

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}
pub fn stop_requested() -> bool {
    STOP.get().map(|p| p.exists()).unwrap_or(false)
}
pub fn state_path() -> PathBuf {
    util::state_dir().join("state.json")
}
pub fn read_state() -> Option<StateData> {
    serde_json::from_str(&std::fs::read_to_string(state_path()).ok()?).ok()
}

fn flush() {
    let json = {
        let mut s = STATE.lock().unwrap();
        s.ts = now_ms();
        match serde_json::to_string(&*s) {
            Ok(j) => j,
            Err(_) => return,
        }
    };
    let p = state_path();
    let tmp = p.with_extension("tmp");
    if std::fs::write(&tmp, json).is_ok() {
        let _ = std::fs::rename(tmp, p);
    }
}

pub fn set_state(phase: &str, msg: &str, progress: Option<u8>) {
    {
        let mut s = STATE.lock().unwrap();
        s.phase = phase.into();
        s.message = msg.into();
        s.progress = progress;
        if phase == "up" {
            s.since = now_ms();
        }
    }
    flush();
}

fn init_logging() {
    let log = util::state_dir().join("core.log");
    let _ = std::fs::remove_file(&log);
    if let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(log) {
        let _ = tracing_subscriber::fmt().with_writer(Mutex::new(f)).with_ansi(false).try_init();
    }
}

pub fn core_main(args: &[String]) -> i32 {
    let get = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned();
    let (Some(profile), Some(stop)) = (get("--core"), get("--stop")) else {
        return 2;
    };
    let _ = STOP.set(PathBuf::from(stop));
    STATE.lock().unwrap().id = get("--id").unwrap_or_default();

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio");
    rt.block_on(async move {
        if util::ensure_root().is_err() || util::init_state_dir().is_err() {
            return 3;
        }
        init_logging();
        set_state("starting", "Подготовка…", None);
        let hb = tokio::spawn(async {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                flush();
            }
        });
        let res: anyhow::Result<()> = async {
            let p = Profile::load(Path::new(&profile))?;
            backend::run(p).await
        }
        .await;
        hb.abort();
        match res {
            Ok(()) => {
                set_state("stopped", "", None);
                0
            }
            Err(e) => {
                set_state("error", &format!("{e:#}"), None);
                1
            }
        }
    })
}
