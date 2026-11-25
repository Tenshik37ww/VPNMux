#!/usr/bin/env python3
"""Закрепляет URL и SHA-256 компонентов в src-tauri/components.json.

  python scripts/pin_components.py            # заполнить недостающее
  python scripts/pin_components.py --refresh  # пересчитать все закреплённые хэши

Записи с `github` разрешаются в точный URL последнего релиза (или указанного tag).
Записи с `hashes_url` (Hysteria) хэши берут у издателя во время работы — тут пропускаются.
ВАЖНО: хэши, посчитанные этим скриптом, — это «доверие в момент закрепления».
Сверьте их с хэшами на сайтах издателей (OpenVPN, wintun) и просмотрите diff перед релизом.
"""
import hashlib, json, pathlib, re, sys, urllib.request

P = pathlib.Path(__file__).resolve().parent.parent / "src-tauri" / "components.json"

def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "vpnmux-pin"})
    return urllib.request.urlopen(req, timeout=180).read()

m = json.loads(P.read_text(encoding="utf-8"))
for name, plats in m["components"].items():
    for key, e in plats.items():
        gh = e.get("github")
        if gh:
            api = f"https://api.github.com/repos/{gh['repo']}/releases/" + (f"tags/{gh['tag']}" if gh.get("tag") else "latest")
            rel = json.loads(get(api))
            a = next((a for a in rel["assets"] if re.fullmatch(gh["asset"], a["name"])), None)
            if not a:
                sys.exit(f"{name}/{key}: в {gh['repo']} ({rel['tag_name']}) нет ассета {gh['asset']}")
            e["url"], e["sha256"] = a["browser_download_url"], ""
        if e.get("hashes_url") or not e.get("url"):
            continue
        if e.get("sha256") and "--refresh" not in sys.argv and not gh:
            continue
        e["sha256"] = hashlib.sha256(get(e["url"])).hexdigest()
        print(f"{name}/{key}: {e['sha256']}  {e['url']}")
P.write_text(json.dumps(m, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
