//! GUI-часть: профили, геолокация серверов, запуск ядра с повышением прав, статус.

use crate::{config::Profile, daemon};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};
use tauri::{AppHandle, Manager, State};

#[derive(Default)]
struct AppState {
    spawn_ms: Mutex<u64>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ProfileInfo {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub endpoint: String,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub place: String,
}

#[derive(Serialize)]
struct Status {
    phase: String,
    message: String,
    progress: Option<u8>,
    since: u64,
    id: String,
}

fn e2s<E: std::fmt::Display>(e: E) -> String {
    format!("{e:#}")
}
fn tq(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_default()
}
fn safe(id: &str) -> Result<(), String> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("некорректный id профиля".into());
    }
    Ok(())
}
fn data(app: &AppHandle) -> Result<PathBuf, String> {
    let d = app.path().app_data_dir().map_err(e2s)?;
    fs::create_dir_all(d.join("profiles")).map_err(e2s)?;
    fs::create_dir_all(d.join("ctl")).map_err(e2s)?;
    Ok(d)
}
fn load_idx(d: &Path) -> Vec<ProfileInfo> {
    fs::read_to_string(d.join("profiles/index.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}
fn save_idx(d: &Path, v: &[ProfileInfo]) -> Result<(), String> {
    fs::write(d.join("profiles/index.json"), serde_json::to_string_pretty(v).map_err(e2s)?).map_err(e2s)
}
fn host_of(ep: &str) -> String {
    ep.rsplit_once(':').map(|(h, _)| h).unwrap_or(ep).trim_matches(|c| c == '[' || c == ']').to_string()
}

/// (широта, долгота, "Город, Страна"); пустой host — собственный IP.
async fn geolocate(host: &str) -> Option<(f64, f64, String)> {
    let ip = if host.is_empty() {
        String::new()
    } else {
        tokio::net::lookup_host((host, 0)).await.ok()?.next()?.ip().to_string()
    };
    let v: serde_json::Value = reqwest::get(format!("https://ipwho.is/{ip}")).await.ok()?.json().await.ok()?;
    if v["success"].as_bool() == Some(false) {
        return None;
    }
    Some((
        v["latitude"].as_f64()?,
        v["longitude"].as_f64()?,
        format!("{}, {}", v["city"].as_str().unwrap_or(""), v["country"].as_str().unwrap_or("")),
    ))
}

async fn store(app: &AppHandle, name: String, toml: String) -> Result<ProfileInfo, String> {
    let p = Profile::parse(&toml).map_err(e2s)?;
    let d = data(app)?;
    let id = format!("{:x}", daemon::now_ms());
    crate::util::write_secret(&d.join(format!("profiles/{id}.toml")), &toml).map_err(e2s)?;
    let ep = p.endpoint();
    let geo = geolocate(&host_of(&ep)).await;
    let info = ProfileInfo {
        id,
        name,
        protocol: p.protocol_id().into(),
        endpoint: ep,
        lat: geo.as_ref().map(|g| g.0),
        lon: geo.as_ref().map(|g| g.1),
        place: geo.map(|g| g.2).unwrap_or_default(),
    };
    let mut v = load_idx(&d);
    v.insert(0, info.clone());
    save_idx(&d, &v)?;
    Ok(info)
}

#[tauri::command]
fn profiles(app: AppHandle) -> Result<Vec<ProfileInfo>, String> {
    Ok(load_idx(&data(&app)?))
}

#[tauri::command]
async fn save_profile(app: AppHandle, name: String, toml: String) -> Result<ProfileInfo, String> {
    store(&app, name, toml).await
}

#[tauri::command]
async fn save_openvpn(
    app: AppHandle,
    name: String,
    ovpn: String,
    username: Option<String>,
    password: Option<String>,
) -> Result<ProfileInfo, String> {
    let d = data(&app)?;
    let id = format!("o{:x}", daemon::now_ms());
    let path = d.join(format!("profiles/{id}.ovpn"));
    crate::util::write_secret(&path, &ovpn).map_err(e2s)?;
    let mut t = format!("protocol = \"openvpn\"\nconfig = {}\n", tq(&path.to_string_lossy()));
    if let (Some(u), Some(p)) = (username.filter(|s| !s.is_empty()), password) {
        t += &format!("username = {}\npassword = {}\n", tq(&u), tq(&p));
    }
    store(&app, name, t).await
}

#[tauri::command]
fn delete_profile(app: AppHandle, id: String) -> Result<(), String> {
    safe(&id)?;
    let d = data(&app)?;
    let v: Vec<_> = load_idx(&d).into_iter().filter(|p| p.id != id).collect();
    save_idx(&d, &v)?;
    for ext in ["toml", "ovpn"] {
        let _ = fs::remove_file(d.join(format!("profiles/{id}.{ext}")));
    }
    Ok(())
}

#[tauri::command]
fn export_toml(app: AppHandle, id: String) -> Result<String, String> {
    safe(&id)?;
    let t = fs::read_to_string(data(&app)?.join(format!("profiles/{id}.toml"))).map_err(e2s)?;
    Ok(t.lines()
        .map(|l| {
            let k = l.split('=').next().unwrap_or("").trim();
            if ["private_key", "password", "preshared_key", "obfs_password"].contains(&k) {
                format!("{k} = \"***\"")
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

#[cfg(windows)]
fn spawn_core(exe: &Path, pf: &Path, stop: &Path, id: &str) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    // приложение уже запущено от администратора (манифест) — потомок наследует права
    std::process::Command::new(exe)
        .arg("--core").arg(pf).arg("--stop").arg(stop).args(["--id", id])
        .creation_flags(0x0800_0000)
        .spawn().map(|_| ()).map_err(e2s)
}

#[cfg(target_os = "macos")]
fn spawn_core(exe: &Path, pf: &Path, stop: &Path, id: &str) -> Result<(), String> {
    let q = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
    let sh = format!(
        "{} --core {} --stop {} --id {} >/dev/null 2>&1 &",
        q(&exe.to_string_lossy()), q(&pf.to_string_lossy()), q(&stop.to_string_lossy()), q(id)
    );
    let osa = format!(
        "do shell script \"{}\" with administrator privileges with prompt \"vpnmux: создать VPN-туннель\"",
        sh.replace('\\', "\\\\").replace('"', "\\\"")
    );
    let o = std::process::Command::new("osascript").args(["-e", &osa]).output().map_err(e2s)?;
    if o.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&o.stderr).trim().to_string()) }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn spawn_core(exe: &Path, pf: &Path, stop: &Path, id: &str) -> Result<(), String> {
    std::process::Command::new("pkexec")
        .arg(exe).arg("--core").arg(pf).arg("--stop").arg(stop).args(["--id", id])
        .spawn().map(|_| ()).map_err(e2s)
}

#[tauri::command]
async fn connect(app: AppHandle, st: State<'_, AppState>, id: String) -> Result<(), String> {
    safe(&id)?;
    let d = data(&app)?;
    let pf = d.join(format!("profiles/{id}.toml"));
    if !pf.is_file() {
        return Err("профиль не найден".into());
    }
    if let Some(s) = daemon::read_state() {
        let active = matches!(s.phase.as_str(), "starting" | "downloading" | "connecting" | "up");
        if active && daemon::now_ms().saturating_sub(s.ts) < 8000 {
            return Err("туннель уже запущен".into());
        }
    }
    let stop = d.join("ctl/stop");
    let _ = fs::remove_file(&stop);
    *st.spawn_ms.lock().unwrap() = daemon::now_ms();
    let exe = std::env::current_exe().map_err(e2s)?;
    let r = tauri::async_runtime::spawn_blocking(move || spawn_core(&exe, &pf, &stop, &id))
        .await
        .map_err(e2s)?;
    if r.is_err() {
        *st.spawn_ms.lock().unwrap() = 0;
    }
    r
}

#[tauri::command]
fn disconnect(app: AppHandle) -> Result<(), String> {
    fs::write(data(&app)?.join("ctl/stop"), "").map_err(e2s)
}

#[tauri::command]
fn status(st: State<'_, AppState>) -> Status {
    let spawn = *st.spawn_ms.lock().unwrap();
    let now = daemon::now_ms();
    let mk = |p: &str, m: &str| Status { phase: p.into(), message: m.into(), progress: None, since: 0, id: String::new() };
    match daemon::read_state() {
        // состояние от прошлого запуска (раньше нашего spawn) игнорируем
        Some(s) if s.ts + 1000 >= spawn => {
            let active = matches!(s.phase.as_str(), "starting" | "downloading" | "connecting" | "up");
            if active && now.saturating_sub(s.ts) > 8000 {
                return mk("stopped", "Служба туннеля перестала отвечать");
            }
            Status { phase: s.phase, message: s.message, progress: s.progress, since: s.since, id: s.id }
        }
        _ if spawn > 0 && now.saturating_sub(spawn) < 120_000 => mk("starting", "Ожидание запуска…"),
        _ => mk("idle", ""),
    }
}

#[tauri::command]
async fn my_location() -> Option<(f64, f64, String)> {
    geolocate("").await
}

pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            profiles, save_profile, save_openvpn, delete_profile, export_toml, connect, disconnect, status, my_location
        ])
        .build(tauri::generate_context!())
        .expect("ошибка запуска tauri")
        .run(|app, ev| {
            // при выходе из приложения просим ядро закрыть туннель
            if let tauri::RunEvent::Exit = ev {
                if let Ok(d) = app.path().app_data_dir() {
                    let _ = fs::write(d.join("ctl/stop"), "");
                }
            }
        });
}
