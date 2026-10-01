#!/bin/bash
# Устанавливает vpn-policy-poc: служба (root, launchd) + значок в строке меню.
set -euo pipefail
cd "$(dirname "$0")"
[ "$(id -u)" = 0 ] || exec sudo "$0" "$@"

DIR=/usr/local/vpnpoc
LABEL=local.vpn-policy-poc
PLIST=/Library/LaunchDaemons/$LABEL.plist
TRAY_LABEL=$LABEL.tray
TRAY_PLIST=/Library/LaunchAgents/$TRAY_LABEL.plist
APP="/Applications/VPN Policy.app"
USER_ID=$(id -u "${SUDO_USER:-$(stat -f %Su /dev/console)}")

launchctl bootout system/$LABEL 2>/dev/null || true
launchctl bootout gui/$USER_ID/$TRAY_LABEL 2>/dev/null || true
pkill -x vpnpoc 2>/dev/null && sleep 1 || true      # ручной экземпляр, если запущен
pkill -x vpnpoc-tray 2>/dev/null || true

mkdir -p "$DIR"
install -m 755 vpnpoc "$DIR/vpnpoc"
# Новый config.yaml ставим всегда (в нём новые правила); прежний — в .bak.
if [ -f "$DIR/config.yaml" ] && ! cmp -s config.yaml "$DIR/config.yaml"; then
  cp "$DIR/config.yaml" "$DIR/config.yaml.bak"
  echo "config.yaml обновлён, прежний сохранён как $DIR/config.yaml.bak"
fi
install -m 644 config.yaml "$DIR/config.yaml"
install -m 755 test.sh "$DIR/test.sh"
install -m 755 uninstall.sh "$DIR/uninstall.sh"
rm -rf "$APP"; cp -R "VPN Policy.app" "$APP"
xattr -dr com.apple.quarantine "$DIR" "$APP" 2>/dev/null || true

cat > "$PLIST" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array>
    <string>$DIR/vpnpoc</string><string>daemon</string>
    <string>-c</string><string>$DIR/config.yaml</string>
    <string>-state</string><string>$DIR/state</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>/var/log/vpnpoc.log</string>
  <key>StandardErrorPath</key><string>/var/log/vpnpoc.log</string>
</dict></plist>
PL
cat > "$TRAY_PLIST" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$TRAY_LABEL</string>
  <key>ProgramArguments</key><array><string>$APP/Contents/MacOS/vpnpoc-tray</string></array>
  <key>RunAtLoad</key><true/>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
</dict></plist>
PL
chmod 644 "$PLIST" "$TRAY_PLIST"
launchctl bootstrap system "$PLIST"
launchctl bootstrap gui/$USER_ID "$TRAY_PLIST" 2>/dev/null || true
sleep 2
echo "Установлено. Значок — в строке меню справа вверху. Лог: tail -f /var/log/vpnpoc.log"
tail -n 10 /var/log/vpnpoc.log || true
