#!/bin/bash
# Полностью удаляет vpn-policy-poc. Служба при остановке сама убирает свои маршруты и DNS.
[ "$(id -u)" = 0 ] || exec sudo "$0" "$@"
USER_ID=$(id -u "${SUDO_USER:-$(stat -f %Su /dev/console)}")
launchctl bootout gui/$USER_ID/local.vpn-policy-poc.tray 2>/dev/null
pkill -x vpnpoc-tray 2>/dev/null
launchctl bootout system/local.vpn-policy-poc 2>/dev/null
sleep 2
rm -f /Library/LaunchDaemons/local.vpn-policy-poc.plist /Library/LaunchAgents/local.vpn-policy-poc.tray.plist
rm -rf "/Applications/VPN Policy.app"
# Страховка на случай, если агент был убит без очистки.
grep -l "managed by vpn-policy-poc" /etc/resolver/* 2>/dev/null | xargs rm -f
route -n delete 77.234.220.42/32 >/dev/null 2>&1
dscacheutil -flushcache; killall -HUP mDNSResponder
rm -rf /usr/local/vpnpoc
echo "Удалено. Лог оставлен: /var/log/vpnpoc.log"
