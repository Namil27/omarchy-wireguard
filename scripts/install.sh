#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
config_dir="${XDG_CONFIG_HOME:-$HOME/.config}"
data_dir="${XDG_DATA_HOME:-$HOME/.local/share}"
bin_dir="${XDG_BIN_HOME:-$HOME/.local/bin}"
lib_dir="$data_dir/omarchy-wireguard"
plugin_dir="$config_dir/omarchy/plugins/namil27.wireguard"
shell_config="$config_dir/omarchy/shell.json"

if [[ ! -f "$shell_config" ]] || ! command -v omarchy >/dev/null; then
  printf 'Omarchy Shell configuration and CLI are required.\n' >&2
  exit 1
fi

backup() {
  if [[ -e "$1" || -L "$1" ]]; then
    cp -p -- "$1" "$1.bak.$(date +%Y%m%d-%H%M%S).$$"
  fi
}

mkdir -p "$bin_dir" "$lib_dir" "$plugin_dir"
backup "$shell_config"
backup "$lib_dir/omarchy_wireguard.py"
backup "$lib_dir/rofi.rasi"
backup "$bin_dir/omarchy-wireguard"
backup "$plugin_dir/manifest.json"
backup "$plugin_dir/BarWidget.qml"

install -m 755 "$root/src/omarchy_wireguard.py" "$lib_dir/omarchy_wireguard.py"
install -m 644 "$root/examples/rofi.rasi" "$lib_dir/rofi.rasi"
printf '#!/usr/bin/env bash\nexec python3 %q "$@"\n' "$lib_dir/omarchy_wireguard.py" > "$bin_dir/omarchy-wireguard"
chmod 755 "$bin_dir/omarchy-wireguard"
install -m 644 "$root/omarchy-plugin/manifest.json" "$plugin_dir/manifest.json"
python3 - "$root/omarchy-plugin/BarWidget.qml" "$plugin_dir/BarWidget.qml" "$bin_dir/omarchy-wireguard" <<'PY'
import json
from pathlib import Path
import sys
template, output, command = map(Path, sys.argv[1:])
output.write_text(template.read_text().replace("@COMMAND@", json.dumps(str(command))[1:-1]))
output.chmod(0o644)
PY

omarchy plugin validate "$plugin_dir"
if ! jq -e 'any(.bar.layout[][]?; .id == "namil27.wireguard")' "$shell_config" >/dev/null; then
  omarchy shell shell rescanPlugins
  omarchy plugin enable namil27.wireguard --section right
fi
if ! omarchy restart shell; then
  printf 'Omarchy Shell will load the updated widget at the next login.\n' >&2
fi
printf 'Installed Omarchy Shell WireGuard widget.\n'
