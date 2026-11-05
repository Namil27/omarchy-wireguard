#!/usr/bin/env bash
set -euo pipefail

config_dir="${XDG_CONFIG_HOME:-$HOME/.config}"
data_dir="${XDG_DATA_HOME:-$HOME/.local/share}"
bin_dir="${XDG_BIN_HOME:-$HOME/.local/bin}"
plugin_dir="$config_dir/omarchy/plugins/namil27.wireguard"
shell_config="$config_dir/omarchy/shell.json"

if [[ -f "$shell_config" ]]; then
  cp -p -- "$shell_config" "$shell_config.bak.$(date +%Y%m%d-%H%M%S).$$"
  if command -v omarchy >/dev/null; then
    omarchy plugin disable namil27.wireguard || true
  fi
fi
python3 - "$bin_dir" "$data_dir" "$plugin_dir" <<'PY'
from pathlib import Path
import sys
bin_dir, data_dir, plugin_dir = map(Path, sys.argv[1:])
for path in [
    bin_dir / "omarchy-wireguard",
    data_dir / "omarchy-wireguard/omarchy_wireguard.py",
    data_dir / "omarchy-wireguard/rofi.rasi",
    plugin_dir / "manifest.json",
    plugin_dir / "BarWidget.qml",
]:
    path.unlink(missing_ok=True)
for directory in [plugin_dir, data_dir / "omarchy-wireguard"]:
    if directory.exists() and not any(directory.iterdir()):
        directory.rmdir()
PY
if command -v omarchy >/dev/null; then
  omarchy restart shell >/dev/null 2>&1 || true
fi
printf 'Program removed. NetworkManager profiles and app state were preserved.\n'
