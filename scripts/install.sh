#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${XDG_BIN_HOME:-$HOME/.local/bin}"
lib_dir="${XDG_DATA_HOME:-$HOME/.local/share}/waybar-wireguard"
service_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
backup() {
  if [[ -e "$1" || -L "$1" ]]; then
    mv -- "$1" "$1.bak.$(date +%Y%m%d-%H%M%S)"
  fi
}
mkdir -p "$bin_dir" "$lib_dir" "$service_dir"
backup "$lib_dir/waybar_wireguard.py"
backup "$lib_dir/rofi.rasi"
backup "$bin_dir/waybar-wireguard"
backup "$service_dir/waybar-wireguard-watch.service"
install -m 755 "$root/src/waybar_wireguard.py" "$lib_dir/waybar_wireguard.py"
install -m 644 "$root/examples/rofi.rasi" "$lib_dir/rofi.rasi"
printf '#!/usr/bin/env bash\nexec python3 %q "$@"\n' "$lib_dir/waybar_wireguard.py" > "$bin_dir/waybar-wireguard"
chmod 755 "$bin_dir/waybar-wireguard"
sed "s|@COMMAND@|$bin_dir/waybar-wireguard|g" "$root/examples/waybar-wireguard-watch.service" > "$service_dir/waybar-wireguard-watch.service"
systemctl --user daemon-reload
systemctl --user enable --now waybar-wireguard-watch.service
printf 'Installed. Add the module from examples/waybar.jsonc to your Waybar configuration.\n'
