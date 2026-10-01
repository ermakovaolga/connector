#!/bin/bash
# Проверка работающего агента (запускать во втором терминале, sudo не нужен).
#   ./test.sh                      — ITMO: d.dgx:18888
#   ./test.sh example.com https    — self-test
HOST=${1:-d.dgx}
SCHEME=${2:-http}
PORT=${3:-$([ "$SCHEME" = https ] && echo 443 || echo 18888)}
URL="$SCHEME://$HOST:$PORT/"

echo "== 1. DNS: $HOST должен резолвиться в fake IP 198.18.x.x (через /etc/resolver)"
IP=$(dscacheutil -q host -a name "$HOST" | awk '/ip_address/{print $2; exit}')
echo "   $HOST -> ${IP:-<нет ответа>}"
case "$IP" in 198.18.*) echo "   OK";; *) echo "   FAIL"; exit 1;; esac

echo "== 2. Маршрут: fake IP должен идти в TUN агента"
IFACE=$(route -n get "$IP" | awk '/interface:/{print $2}')
echo "   $IP -> $IFACE"

echo "== 3. Трафик: $URL через TUN -> policy -> outbound"
curl -s -o /dev/null --connect-timeout 5 -m 10 \
  -w "   HTTP %{http_code}, remote %{remote_ip}, connect %{time_connect}s, total %{time_total}s\n" "$URL"

echo "== 4. Контроль: обычный интернет не затронут агентом"
curl -s -o /dev/null --connect-timeout 5 -m 10 -w "   https://1.1.1.1 -> HTTP %{http_code}\n" https://1.1.1.1
echo "   8.8.8.8 -> $(route -n get 8.8.8.8 | awk '/interface:/{print $2}')"

echo "== В логе агента должна быть строка вида:"
echo "   tcp  198.18.1.x:$PORT ($HOST -> <real IP>) -> <outbound>[<iface>] connected"
