#!/bin/bash
cd "$(dirname "$0")"

# Kiem tra quyen root
if [ "$EUID" -ne 0 ]; then
  echo "[!] Vui long chay script nay bang quyen root!"
  echo "Lenh chay: sudo ./run_lan_watcher_admin.sh"
  exit 1
fi

echo "========================================================"
echo "              LAN WATCHER PRO 2026"
echo "========================================================"
echo "[*] Dang chay LAN Watcher table dashboard..."
echo ""
python3 "$(dirname "$0")/realtime_lan_watcher_deep.py" --profile aggressive --ui-mode table --offline-after 10

echo ""
echo "LAN Watcher Pro exited."
