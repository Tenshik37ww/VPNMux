//! Автозагрузка внешних компонентов (hysteria, wintun, AmneziaWG, OpenVPN) по манифесту
//! components.json. Каждый файл проверяется по SHA-256 (закреплённому в манифесте или
//! из hashes-файла издателя) ДО установки/запуска; при несовпадении установка отменяется.

use crate::{daemon::set_state, util};
use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::{Cursor, Read},
    path::{Path, PathBuf},
};

const MANIFEST: &str = include_str!("../components.json");

#[derive(Deserialize, Clone)]
struct Entry {
    #[serde(default)]
    url: String,
    #[serde(default)]
    sha256: String,
    hashes_url: Option<String>,
    hash_name: Option<String>,
    #[serde(default = "d_kind")]
    kind: String,
    #[serde(default)]
    files: HashMap<String, String>,
    bin: String,
}
fn d_kind() -> String {
    "bin".into()
}
#[derive(Deserialize)]
struct Manifest {
    components: HashMap<String, HashMap<String, Entry>>,
}

fn expand(s: &str) -> String {
    let (mut out, mut rest) = (String::new(), s);
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        rest = &rest[i + 1..];
        match rest.find('%') {
            Some(j) => {
                out.push_str(&std::env::var(&rest[..j]).unwrap_or_default());
                rest = &rest[j + 1..];
            }
            None => {
                out.push('%');
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

fn make_exec(p: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755))?;
    }
    let _ = p;
    Ok(())
}

async fn expected(e: &Entry) -> Result<String> {
    if !e.sha256.is_empty() {
        return Ok(e.sha256.to_lowercase());
    }
    if let (Some(u), Some(n)) = (&e.hashes_url, &e.hash_name) {
        let t = reqwest::get(u).await?.error_for_status()?.text().await?;
        for l in t.lines() {
            let mut it = l.split_whitespace();
            if let (Some(h), Some(f)) = (it.next(), it.next_back()) {
                if f.trim_start_matches('*').rsplit('/').next() == Some(n.as_str()) {
                    return Ok(h.to_lowercase());
                }
            }
        }
        bail!("в {u} нет контрольной суммы для {n}");
    }
    bail!("для компонента не закреплён sha256: запустите scripts/pin_components.py и пересоберите приложение")
}

/// Гарантирует наличие компонента; возвращает путь к его главному файлу.
pub async fn ensure(name: &str) -> Result<PathBuf> {
    let m: Manifest = serde_json::from_str(MANIFEST).context("components.json")?;
    let key = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let e = m
        .components
        .get(name)
        .and_then(|p| p.get(&key))
        .cloned()
        .ok_or_else(|| anyhow!("компонент `{name}` недоступен для платформы {key}"))?;
    let dir = util::components_dir()?.join(name);
    std::fs::create_dir_all(&dir)?;
    let bin = if e.kind == "msi" { PathBuf::from(expand(&e.bin)) } else { dir.join(&e.bin) };
    let marker = dir.join(".installed");

    let want = match expected(&e).await {
        Ok(h) => h,
        Err(err) => {
            if bin.exists() {
                return Ok(bin); // офлайн: работаем с уже установленным
            }
            return Err(err);
        }
    };
    if bin.exists() && std::fs::read_to_string(&marker).map(|s| s.trim() == want).unwrap_or(false) {
        return Ok(bin);
    }
    if e.url.is_empty() {
        bail!("для `{name}` не задан url: запустите scripts/pin_components.py");
    }

    let label = format!("Загрузка {name}…");
    set_state("downloading", &label, Some(0));
    let mut resp = reqwest::get(&e.url)
        .await
        .with_context(|| format!("загрузка {}", e.url))?
        .error_for_status()?;
    let total = resp.content_length().unwrap_or(0);
    let (mut buf, mut last) = (Vec::new(), 0u8);
    while let Some(c) = resp.chunk().await? {
        buf.extend_from_slice(&c);
        if total > 0 {
            let pct = (buf.len() as u64 * 100 / total) as u8;
            if pct != last {
                last = pct;
                set_state("downloading", &label, Some(pct));
            }
        }
    }
    let got = hex::encode(Sha256::digest(&buf));
    if got != want {
        bail!("контрольная сумма `{name}` не совпала (ожидалось {want}, получено {got}): установка отменена");
    }

    set_state("downloading", &format!("Установка {name}…"), None);
    match e.kind.as_str() {
        "bin" => {
            std::fs::write(&bin, &buf)?;
            make_exec(&bin)?;
        }
        "zip" => {
            let mut z = zip::ZipArchive::new(Cursor::new(&buf))?;
            for (src, dst) in &e.files {
                let mut f = z.by_name(src).with_context(|| format!("`{src}` не найден в архиве"))?;
                let mut out = Vec::new();
                f.read_to_end(&mut out)?;
                std::fs::write(dir.join(dst), out)?;
            }
        }
        "tgz" => {
            let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(&buf[..]));
            for en in ar.entries()? {
                let mut en = en?;
                let p = en.path()?.to_string_lossy().trim_start_matches("./").to_string();
                if let Some(dst) = e.files.get(&p) {
                    let mut out = Vec::new();
                    en.read_to_end(&mut out)?;
                    let t = dir.join(dst);
                    std::fs::write(&t, out)?;
                    make_exec(&t)?;
                }
            }
        }
        "msi" => {
            let pkg = dir.join("package.msi");
            std::fs::write(&pkg, &buf)?;
            let st = util::cmd("msiexec").arg("/i").arg(&pkg).args(["/qn", "/norestart"]).status().await?;
            if !st.success() && st.code() != Some(3010) {
                bail!("msiexec завершился с ошибкой: {st}");
            }
        }
        k => bail!("неизвестный тип компонента `{k}`"),
    }
    if !bin.exists() {
        bail!("после установки не найден {}", bin.display());
    }
    std::fs::write(&marker, &want)?;
    Ok(bin)
}
