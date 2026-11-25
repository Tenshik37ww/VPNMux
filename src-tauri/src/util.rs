use anyhow::{bail, Context, Result};
use std::{
    ffi::OsStr,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::process::{Child, Command};

// Каталоги ядра принадлежат администратору/root: компоненты запускаются с повышенными правами,
// поэтому обычный пользователь не должен иметь права их подменить.
#[cfg(windows)]
pub fn base_dir() -> PathBuf {
    PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into())).join("vpnmux")
}
#[cfg(target_os = "macos")]
pub fn base_dir() -> PathBuf {
    PathBuf::from("/Library/Application Support/vpnmux")
}
#[cfg(all(unix, not(target_os = "macos")))]
pub fn base_dir() -> PathBuf {
    PathBuf::from("/var/lib/vpnmux")
}

pub fn state_dir() -> PathBuf {
    base_dir().join("run")
}

fn mk(p: PathBuf, _mode: u32) -> Result<PathBuf> {
    std::fs::create_dir_all(&p).with_context(|| format!("создание {}", p.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(_mode))?;
    }
    Ok(p)
}

fn init_base() -> Result<PathBuf> {
    let b = mk(base_dir(), 0o755)?;
    #[cfg(windows)]
    {
        // только Администраторы и SYSTEM; наследуется дочерними каталогами
        let _ = std::process::Command::new("icacls")
            .arg(&b)
            .args(["/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"])
            .output();
    }
    Ok(b)
}

pub fn init_state_dir() -> Result<PathBuf> {
    init_base()?;
    mk(state_dir(), 0o755)
}
pub fn components_dir() -> Result<PathBuf> {
    init_base()?;
    mk(base_dir().join("components"), 0o755)
}
/// Каталог для временных конфигов с секретами (0700).
pub fn runtime_dir() -> Result<PathBuf> {
    init_state_dir()?;
    mk(state_dir().join("s"), 0o700)
}

pub fn write_secret(path: &Path, content: &str) -> Result<()> {
    let _ = std::fs::remove_file(path);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path).with_context(|| format!("создание {}", path.display()))?;
    f.write_all(content.as_bytes())?;
    Ok(())
}

#[cfg(unix)]
pub fn is_elevated() -> bool {
    unsafe { libc::geteuid() == 0 }
}
#[cfg(windows)]
pub fn is_elevated() -> bool {
    unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
}
pub fn ensure_root() -> Result<()> {
    if !is_elevated() {
        bail!("нужны права администратора (root) для создания туннеля");
    }
    Ok(())
}

/// Команда без всплывающего консольного окна на Windows.
pub fn cmd(bin: impl AsRef<OsStr>) -> Command {
    #[allow(unused_mut)]
    let mut c = Command::new(bin);
    #[cfg(windows)]
    {
        c.creation_flags(0x0800_0000);
    }
    c
}

/// Лог дочерних процессов → run/core.log
pub fn log_stdio() -> std::process::Stdio {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(state_dir().join("core.log"))
        .map(Into::into)
        .unwrap_or_else(|_| std::process::Stdio::null())
}

pub async fn run_in(bin: &Path, args: &[&str], path_prepend: Option<&Path>, envs: &[(&str, &str)]) -> Result<()> {
    let mut c = cmd(bin);
    c.args(args);
    for (k, v) in envs {
        c.env(k, v);
    }
    if let Some(d) = path_prepend {
        let mut paths = vec![d.to_path_buf()];
        if let Some(p) = std::env::var_os("PATH") {
            paths.extend(std::env::split_paths(&p));
        }
        c.env("PATH", std::env::join_paths(paths)?);
    }
    let o = c
        .output()
        .await
        .with_context(|| format!("не удалось запустить `{}` (установлен ли он?)", bin.display()))?;
    if !o.status.success() {
        bail!(
            "`{}` завершился с ошибкой ({}): {}",
            bin.display(),
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    Ok(())
}

pub async fn run_checked(bin: &str, args: &[&str]) -> Result<()> {
    run_in(Path::new(bin), args, None, &[]).await
}

pub async fn output(bin: &str, args: &[&str]) -> Result<String> {
    let o = cmd(bin)
        .args(args)
        .output()
        .await
        .with_context(|| format!("не удалось запустить `{bin}`"))?;
    if !o.status.success() {
        bail!("`{bin}` завершился с ошибкой: {}", o.status);
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Мягко остановить дочерний процесс: SIGTERM (Windows: TerminateProcess), затем kill по таймауту.
pub async fn terminate(child: &mut Child, grace: Duration) {
    #[cfg(unix)]
    {
        if let Some(pid) = child.id() {
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
        }
    }
    #[cfg(windows)]
    {
        let _ = child.start_kill();
    }
    if tokio::time::timeout(grace, child.wait()).await.is_err() {
        let _ = child.kill().await;
    }
}

pub fn check_plain(name: &str, value: &str) -> Result<()> {
    if value.contains(['\n', '\r', '\0']) {
        bail!("поле `{name}` содержит недопустимые символы (перевод строки)");
    }
    Ok(())
}
