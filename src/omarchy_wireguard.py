#!/usr/bin/env python3
"""Omarchy Shell front end for WireGuard connections owned by this application."""
import argparse
import fcntl
import json
import logging
import os
from pathlib import Path
import re
import select
import subprocess
import sys
import tempfile
import time

APP = "omarchy-wireguard"
STATE_DIR = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / APP
STATE = STATE_DIR / "state.json"
LEGACY_STATE = STATE_DIR.parent / "waybar-wireguard/state.json"
LOCK = STATE_DIR / "operation.lock"
LOG = STATE_DIR / "app.log"
UUID = re.compile(r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b")
SAFE_NAME = re.compile(r"^[\w .()\-]{1,64}$", re.UNICODE)
ALLOWED = {
    "Interface": {"PrivateKey", "Address", "DNS", "MTU"},
    "Peer": {"PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"},
}


def setup():
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    if not STATE.exists() and LEGACY_STATE.is_file():
        try:
            legacy = json.loads(LEGACY_STATE.read_text())
            if isinstance(legacy.get("profiles"), dict):
                save(legacy)
        except (OSError, ValueError, TypeError):
            pass
    logging.basicConfig(filename=LOG, level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    if LOG.exists():
        os.chmod(LOG, 0o600)


def read_state():
    try:
        data = json.loads(STATE.read_text())
        if isinstance(data.get("profiles"), dict):
            return data
    except (OSError, ValueError, TypeError):
        pass
    return {"profiles": {}, "quick": None, "busy": None, "error": None}


def save(data):
    fd, name = tempfile.mkstemp(dir=STATE_DIR, prefix=".state-")
    try:
        with os.fdopen(fd, "w") as out:
            json.dump(data, out, ensure_ascii=False, indent=2)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(name, 0o600)
        os.replace(name, STATE)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def run(*args, timeout=30):
    try:
        return subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return subprocess.CompletedProcess(args, 124, "", "")


def nm(*args, timeout=30):
    return run("nmcli", "--wait", str(timeout), *args, timeout=timeout + 2)


def notify(message, urgency="normal"):
    run("notify-send", "-a", APP, "-u", urgency, APP, message, timeout=5)


def owned(data):
    return {k: v for k, v in data["profiles"].items() if UUID.fullmatch(k)}


def active_uuids():
    result = nm("-t", "-f", "UUID", "connection", "show", "--active", timeout=5)
    if result.returncode:
        return None
    return set(UUID.findall(result.stdout))


def active_owned(data):
    active = active_uuids()
    if active is None:
        return None
    return [key for key in owned(data) if key in active]


def handshake(key):
    device = nm("-g", "GENERAL.DEVICES", "connection", "show", key, timeout=5)
    if device.returncode or not device.stdout.strip():
        return "Состояние связи неизвестно"
    iface = device.stdout.strip().splitlines()[0]
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", iface):
        return "Состояние связи неизвестно"
    result = run("wg", "show", iface, "latest-handshakes", timeout=5)
    if result.returncode:
        return "Рукопожатие недоступно для проверки"
    stamps = []
    for line in result.stdout.splitlines():
        try:
            stamps.append(int(line.rsplit("\t", 1)[-1]))
        except ValueError:
            pass
    if stamps and max(stamps) and time.time() - max(stamps) < 180:
        return "Рукопожатие подтверждено за последние 3 минуты"
    return "Туннель включён; свежего рукопожатия нет"


def status():
    data = read_state()
    running = active_owned(data)
    if data.get("busy"):
        label, css = "󰦖 VPN: переключение", "switching"
        tooltip = data["busy"]
    elif running is None:
        label, css, tooltip = "󰦖 VPN: ошибка", "error", "NetworkManager недоступен"
    elif running:
        key = running[0]
        label, css = "󰦖 " + data["profiles"][key], "active"
        tooltip = handshake(key)
        if len(running) > 1:
            css, tooltip = "error", "Активно несколько профилей приложения"
    elif data.get("error"):
        label, css, tooltip = "󰦖 VPN: ошибка", "error", data["error"]
    else:
        label, css, tooltip = "󰦖 VPN: выкл.", "inactive", "Профили приложения отключены"
    print(json.dumps({"text": label, "tooltip": tooltip, "class": css},
                     ensure_ascii=False), flush=True)


def validate_conf(path):
    path = Path(path)
    if path.suffix.lower() != ".conf" or not path.is_file() or path.stat().st_size > 65536:
        raise ValueError("Выберите файл .conf размером до 64 КБ")
    section = None
    peer_count = 0
    interface_count = 0
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (UnicodeError, OSError):
        raise ValueError("Файл не читается как UTF-8") from None
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line in ("[Interface]", "[Peer]"):
            section = line[1:-1]
            peer_count += section == "Peer"
            interface_count += section == "Interface"
            continue
        if "=" not in line or section is None:
            raise ValueError(f"Некорректная строка {number}")
        key = line.split("=", 1)[0].strip()
        if key not in ALLOWED[section]:
            raise ValueError(f"Неподдерживаемый параметр в строке {number}")
    if not peer_count or interface_count != 1:
        raise ValueError("Нужны секции [Interface] и [Peer]")
    return path


def lock_operation():
    handle = open(LOCK, "a+")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        raise ValueError("Другая операция уже выполняется")
    return handle


def fail(data, message):
    data["error"] = message
    save(data)
    logging.error("%s", message)
    notify(message, "critical")


def change(target):
    with lock_operation():
        data = read_state()
        if target and target not in owned(data):
            raise ValueError("Профиль не принадлежит приложению")
        previous = active_owned(data)
        if previous is None:
            raise ValueError("NetworkManager недоступен")
        if len(previous) > 1:
            raise ValueError("Включено несколько профилей приложения; отключите лишние вручную")
        old = previous[0] if previous else None
        if old == target:
            return
        data["busy"], data["error"] = "Переключение профиля", None
        save(data)
        try:
            if old and nm("connection", "down", "uuid", old, timeout=35).returncode:
                raise ValueError("Не удалось отключить предыдущий профиль")
            if target and nm("connection", "up", "uuid", target, timeout=45).returncode:
                raise ValueError("Не удалось включить выбранный профиль")
            if target:
                data["quick"] = target
            logging.info("Профиль переключён")
            notify("Профиль включён" if target else "Профиль отключён")
        except ValueError as exc:
            fail(data, str(exc))
            if old and old != target:
                if choose(["Восстановить предыдущий профиль", "Оставить отключённым"],
                          "Переключение не удалось") == "Восстановить предыдущий профиль":
                    if nm("connection", "up", "uuid", old, timeout=45).returncode:
                        fail(data, "Не удалось восстановить предыдущий профиль")
                    else:
                        notify("Предыдущий профиль восстановлен")
            raise
        finally:
            data["busy"] = None
            save(data)


def import_files(paths):
    with lock_operation():
        data = read_state()
        for raw in paths:
            try:
                path = validate_conf(raw)
                name = path.stem
                if not SAFE_NAME.fullmatch(name):
                    raise ValueError("Имя файла должно содержать только буквы, цифры, пробел, _, -, . или ()")
                result = nm("connection", "import", "type", "wireguard", "file", str(path), timeout=30)
                found = UUID.search(result.stdout)
                if result.returncode or not found:
                    raise ValueError("NetworkManager не смог импортировать конфиг; проверьте параметры и права")
                key = found.group()
                if nm("connection", "modify", "uuid", key, "connection.autoconnect", "no").returncode:
                    nm("connection", "delete", "uuid", key)
                    raise ValueError("Не удалось отключить автоподключение; импорт отменён")
                data["profiles"][key] = name
                data["quick"] = key
                data["error"] = None
                save(data)
                logging.info("Импортирован профиль %s", key)
                notify(f"Импортирован профиль {name}; подключение не включено")
            except ValueError as exc:
                fail(data, f"{Path(raw).name}: {exc}")


def choose(items, prompt="WireGuard"):
    if not items:
        return None
    try:
        command = ["rofi", "-dmenu", "-i", "-p", prompt]
        theme = Path(__file__).with_name("rofi.rasi")
        if theme.is_file():
            command += ["-theme", str(theme)]
        result = subprocess.run(command,
                                input="\n".join(items) + "\n", text=True,
                                capture_output=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        notify("Установите rofi-wayland для меню", "critical")
        return None
    value = result.stdout.strip()
    return value if result.returncode == 0 and value in items else None


def select_files():
    result = run("zenity", "--file-selection", "--multiple", "--separator=\n",
                 "--file-filter=WireGuard configs | *.conf", timeout=300)
    return [p for p in result.stdout.splitlines() if p] if result.returncode == 0 else []


def menu():
    data = read_state()
    active = active_owned(data) or []
    entries = []
    mapping = {}
    for key, name in owned(data).items():
        mark = "●" if key in active else "○"
        label = f"{mark} {name}" + ("  ★" if key == data.get("quick") else "")
        entries.append(label)
        mapping[label] = key
    entries += ["Импортировать .conf…", "Отключить", "Быстрое подключение", "Управление профилями…"]
    selected = choose(entries)
    if selected in mapping:
        change(mapping[selected])
    elif selected == "Импортировать .conf…":
        import_files(select_files())
    elif selected == "Отключить":
        change(None)
    elif selected == "Быстрое подключение" and data.get("quick"):
        change(data["quick"])
    elif selected == "Управление профилями…":
        manage()


def manage():
    data = read_state()
    names = {f"{name} [{key[:8]}]": key for key, name in owned(data).items()}
    selected = choose(list(names), "Профиль")
    if not selected:
        return
    key = names[selected]
    action = choose(["Для быстрого подключения", "Переименовать", "Удалить"], "Действие")
    if action == "Для быстрого подключения":
        with lock_operation():
            data = read_state()
            data["quick"] = key
            save(data)
        notify("Профиль быстрого подключения выбран")
    elif action == "Переименовать":
        result = run("zenity", "--entry", "--title=WireGuard", "--text=Новое имя профиля",
                     f"--entry-text={data['profiles'][key]}", timeout=120)
        name = result.stdout.strip()
        if result.returncode == 0:
            if not SAFE_NAME.fullmatch(name):
                raise ValueError("Имя: до 64 букв, цифр, пробелов или символов _, -, . и ()")
            with lock_operation():
                if nm("connection", "modify", "uuid", key, "connection.id", name).returncode:
                    raise ValueError("Не удалось переименовать профиль")
                data = read_state()
                data["profiles"][key] = name
                save(data)
    elif action == "Удалить":
        result = run("zenity", "--question", "--title=Удаление WireGuard",
                     f"--text=Удалить профиль «{data['profiles'][key]}»?",
                     "--ok-label=Удалить", "--cancel-label=Отмена", timeout=120)
        if result.returncode == 0:
            with lock_operation():
                if key in (active_owned(data) or []):
                    raise ValueError("Сначала отключите профиль")
                if nm("connection", "delete", "uuid", key).returncode:
                    raise ValueError("Не удалось удалить профиль")
                data = read_state()
                data["profiles"].pop(key, None)
                if data.get("quick") == key:
                    data["quick"] = None
                save(data)


def state_version():
    try:
        info = STATE.stat()
        return info.st_ino, info.st_mtime_ns
    except OSError:
        return None


def stream():
    # One long-lived nmcli monitor; cheap state-file checks and a 30 s handshake refresh.
    while True:
        status()
        version = state_version()
        checked = time.monotonic()
        try:
            with subprocess.Popen(["nmcli", "monitor"], stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True, bufsize=1) as proc:
                while proc.poll() is None:
                    readable, _, _ = select.select([proc.stdout], [], [], 1)
                    changed = False
                    if readable:
                        if not proc.stdout.readline():
                            break
                        changed = True
                    current = state_version()
                    if current != version:
                        version = current
                        changed = True
                    now = time.monotonic()
                    if changed or now - checked >= 30:
                        status()
                        checked = now
        except OSError:
            pass
        time.sleep(5)


def main():
    setup()
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["status", "menu", "toggle", "stream", "import", "connect", "disconnect", "list"])
    parser.add_argument("args", nargs="*")
    args = parser.parse_args()
    try:
        if args.command == "status":
            status()
        elif args.command == "menu":
            menu()
        elif args.command == "toggle":
            data = read_state()
            change(None if active_owned(data) else data.get("quick"))
        elif args.command == "stream":
            stream()
        elif args.command == "import":
            import_files(args.args)
        elif args.command == "connect":
            change(args.args[0])
        elif args.command == "disconnect":
            change(None)
        elif args.command == "list":
            print(json.dumps(read_state()["profiles"], ensure_ascii=False))
    except (ValueError, IndexError) as exc:
        logging.error("%s", exc)
        notify(str(exc), "critical")
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
