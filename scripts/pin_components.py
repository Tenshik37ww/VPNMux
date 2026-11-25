#!/usr/bin/env python3
"""Закрепляет URL и SHA-256 компонентов в src-tauri/components.json.

  python scripts/pin_components.py            # заполнить недостающее (недоступное пропускает с предупреждением)
  python scripts/pin_components.py --refresh  # пересчитать все закреплённые хэши
  python scripts/pin_components.py --strict   # завершиться с ошибкой, если что-то не удалось (для CI)

Записи с `github` разрешаются в точный URL последнего релиза (или указанного tag).
Записи с `hashes_url` (Hysteria) хэши берут у издателя во время работы — тут пропускаются.
ВАЖНО: хэши, посчитанные этим скриптом, — это «доверие в момент закрепления».
Сверьте их с хэшами на сайтах издателей (OpenVPN, wintun) и просмотрите diff перед релизом.
"""
import hashlib, json, pathlib, re, sys, urllib.error, urllib.request

P = pathlib.Path(__file__).resolve().parent.parent / "src-tauri" / "components.json"
STRICT = "--strict" in sys.argv
REFRESH = "--refresh" in sys.argv

def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "vpnmux-pin"})
    return urllib.request.urlopen(req, timeout=180).read()

m = json.loads(P.read_text(encoding="utf-8"))
problems = []
for name, plats in m["components"].items():
    for key, e in plats.items():
        try:
            gh = e.get("github")
            if gh:
                api = f"https://api.github.com/repos/{gh['repo']}/releases/" + (f"tags/{gh['tag']}" if gh.get("tag") else "latest")
                try:
                    rel = json.loads(get(api))
                except urllib.error.HTTPError as ex:
                    if ex.code == 404:
                        raise RuntimeError(f"релиз {gh.get('tag', 'latest')} не найден в {gh['repo']} (для macOS сначала запустите workflow `components`)")
                    raise
                a = next((a for a in rel["assets"] if re.fullmatch(gh["asset"], a["name"])), None)
                if not a:
                    raise RuntimeError(f"в релизе {rel['tag_name']} нет ассета {gh['asset']}")
                e["url"], e["sha256"] = a["browser_download_url"], ""
            if e.get("hashes_url") or not e.get("url"):
                continue
            if e.get("sha256") and not REFRESH and not gh:
                continue
            e["sha256"] = hashlib.sha256(get(e["url"])).hexdigest()
            print(f"{name}/{key}: {e['sha256']}  {e['url']}")
        except Exception as ex:
            problems.append(f"{name}/{key}: {ex}")

P.write_text(json.dumps(m, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
for p in problems:
    print("ПРОПУЩЕНО:", p, file=sys.stderr)
if problems and STRICT:
    sys.exit(1)
