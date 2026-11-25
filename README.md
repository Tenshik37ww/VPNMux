# vpnmux — VPN-клиент (Windows / macOS) на Rust + Tauri

Hysteria2, AmneziaWG 1.x, AmneziaWG 2.0, OpenVPN в одном приложении: точечный 3D-глобус с локацией сервера,
меню выбора протокола, импорт `.conf` (AWG 1/2), `.ovpn` и ссылок `hysteria2://`, настройка внешнего вида.

## Сборка
```bash
cargo install tauri-cli --version "^2" --locked
python scripts/pin_components.py     # закрепить версии/хэши загружаемых компонентов
cargo tauri build                    # NSIS-установщик (Windows) / .app + .dmg (macOS)
cargo tauri dev                      # разработка (на Windows запускать из консоли администратора)
```
CI: `.github/workflows/build.yml` (Windows, macOS arm64/x64). До первой сборки замените `Tenshik37ww/VPNMux`
в `src-tauri/components.json` и один раз запустите workflow `components` (собирает amneziawg-go и awg для macOS).
`ui/index.html` открывается и в обычном браузере в демо-режиме (туннель симулируется).

## Как это работает
- Один бинарник, два режима. Обычный запуск — окно. `vpnmux-app --core …` — безоконное **ядро туннеля**, которое
  поднимается с правами администратора: Windows — манифест `requireAdministrator` (UAC при старте приложения),
  macOS — системный запрос пароля (`osascript … with administrator privileges`) при подключении, Linux — `pkexec`.
- Ядро пишет состояние в `state.json` (Windows `%ProgramData%\vpnmux\run`, macOS `/Library/Application Support/vpnmux/run`),
  GUI его читает; остановка — через stop-файл. Закрытие приложения останавливает туннель.
- **Автозагрузка компонентов** (`components.rs` + `components.json`): при первом подключении ядро скачивает нужное,
  **проверяет SHA-256** и только потом ставит/запускает. Всё хранится в каталоге, доступном только администратору.

| Протокол | Windows | macOS |
|---|---|---|
| Hysteria2 | `hysteria` (+ `wintun.dll`), TUN-режим | `hysteria`, TUN-режим |
| AmneziaWG 1.x/2.0 | MSI клиента AmneziaWG → `amneziawg.exe /installtunnelservice` | `amneziawg-go` + `awg setconf` + `ifconfig/route/networksetup` (своя реализация) |
| OpenVPN | MSI OpenVPN (с драйвером), тихая установка | `brew install openvpn` (готовых бинарников нет) |

Геолокация: IP сервера определяется один раз при сохранении профиля через `ipwho.is` (HTTPS); ваша позиция — при запуске.

## Что НЕ проверено (код написан без сборки и запуска)
- Rust-часть не компилировалась (в среде разработки не было cargo): ожидайте мелкие правки при первой сборке.
- UI проверен в Chromium (логика импорта, фильтр протоколов, цикл подключения, глобус).
- Имена ассетов и версии в `components.json` (MSI AmneziaWG, OpenVPN 2.6.14-I001, wintun 0.14.1) нужно сверить
  с реальными релизами; `pin_components.py` падает, если ассет не найден. Хэш wintun вписан по памяти — сверьте с wintun.net.
- Имя службы `AmneziaWGTunnel$<имя>` и ключи `/installtunnelservice` взяты по аналогии с wireguard-windows.
- Для публикации нужны подпись кода (Windows SmartScreen) и подпись + нотаризация (macOS Gatekeeper).
- Kill-switch и защита от утечки DNS на Windows не реализованы; на macOS DNS меняется на время сессии.
