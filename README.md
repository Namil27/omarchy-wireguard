# waybar-wireguard

Управление WireGuard-профилями из Waybar через NetworkManager. Небольшой модуль показывает состояние туннеля, а меню позволяет импортировать, переключать и обслуживать профили без отдельного окна приложения.

Программа работает только с профилями, добавленными через неё. Существующие соединения NetworkManager остаются вне её управления.

## Установка

Нужны NetworkManager, WireGuard Tools, Python 3.10+, Waybar, rofi-wayland, Zenity, libnotify и пользовательский сеанс systemd. На Arch Linux:

```sh
sudo pacman -S networkmanager wireguard-tools python waybar rofi-wayland zenity libnotify
git clone https://github.com/Namil27/waybar-wireguard.git
cd waybar-wireguard
./scripts/install.sh
```

Для операций NetworkManager используется системная авторизация Polkit. Пароль может потребоваться при импорте или переключении профиля.

Добавьте `custom/wireguard` в нужный список модулей Waybar и перенесите его определение из [examples/waybar.jsonc](examples/waybar.jsonc) в свой конфиг. Стили из [examples/waybar.css](examples/waybar.css) можно добавить в `style.css`. Перед правкой существующих файлов сделайте копию. Меню использует [тему rofi Tokyo Night](examples/rofi.rasi); установленную копию можно изменить в `~/.local/share/waybar-wireguard/rofi.rasi`. Для значка нужен Nerd Font.

## Как работает

Импортированные `.conf` сохраняются как соединения NetworkManager без активации и автоподключения. Программа запоминает их UUID в `~/.local/state/waybar-wireguard/state.json` и по умолчанию допускает один активный профиль. При ошибке переключения предлагает восстановить предыдущий.

Индикатор отдельно показывает состояние туннеля и свежесть WireGuard handshake: наличие интерфейса само по себе не считается подтверждением связи с сервером. Пользовательский сервис следит за событиями NetworkManager и обновляет Waybar сигналом, без частого опроса. Неподдерживаемые параметры `.conf` отклоняются с указанием строки; скриптовые хуки не выполняются.

## Диагностика

```sh
~/.local/bin/waybar-wireguard status
systemctl --user status waybar-wireguard-watch.service
tail -n 30 ~/.local/state/waybar-wireguard/app.log
```

Журнал не содержит ключей или содержимого конфигов. Код и тесты доступны в `src/` и `tests/`; запустить тесты можно командой `python3 -m unittest discover -s tests -v`.

## Удаление

```sh
./scripts/uninstall.sh
```

Затем удалите добавленный модуль и стили из Waybar. Удаление программы сохраняет импортированные соединения NetworkManager и локальное состояние. Если они больше не нужны, удалите их отдельно через NetworkManager.

Лицензия — [MIT](LICENSE).
