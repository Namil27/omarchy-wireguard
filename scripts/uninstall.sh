#!/usr/bin/env bash
set -euo pipefail
bin_dir="${XDG_BIN_HOME:-$HOME/.local/bin}"
lib_dir="${XDG_DATA_HOME:-$HOME/.local/share}/waybar-wireguard"
service_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
systemctl --user disable --now waybar-wireguard-watch.service 2>/dev/null || true
rm -f -- "$bin_dir/waybar-wireguard" "$lib_dir/waybar_wireguard.py" "$lib_dir/rofi.rasi" "$service_dir/waybar-wireguard-watch.service"
systemctl --user daemon-reload
printf 'Program removed. Imported NetworkManager profiles and app state were preserved.\n'
