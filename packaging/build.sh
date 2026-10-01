#!/bin/bash
# Собирает dist/vpnpoc-macos.zip для передачи коллегам.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=dist/vpnpoc-macos; rm -rf dist; mkdir -p $OUT
for a in arm64 amd64; do
  GOOS=darwin GOARCH=$a go build -trimpath -ldflags="-s -w" -o dist/vpnpoc-$a .
  (cd tray && CGO_ENABLED=1 GOOS=darwin GOARCH=$a go build -trimpath -ldflags="-s -w" -o ../dist/tray-$a .)
done
lipo -create -output $OUT/vpnpoc dist/vpnpoc-arm64 dist/vpnpoc-amd64
codesign -s - -f $OUT/vpnpoc

APP="$OUT/VPN Policy.app"
mkdir -p "$APP/Contents/MacOS"
lipo -create -output "$APP/Contents/MacOS/vpnpoc-tray" dist/tray-arm64 dist/tray-amd64
cp packaging/Info.plist "$APP/Contents/Info.plist"
codesign -s - -f --deep "$APP"
rm dist/vpnpoc-arm64 dist/vpnpoc-amd64 dist/tray-arm64 dist/tray-amd64

cp config.yaml test.sh packaging/install.sh packaging/uninstall.sh packaging/INSTALL.md $OUT/
(cd dist && zip -qry vpnpoc-macos.zip vpnpoc-macos)
ls -la dist/vpnpoc-macos.zip; for f in $OUT/vpnpoc "$APP/Contents/MacOS/vpnpoc-tray"; do echo "$(basename "$f"): $(lipo -archs "$f")"; done
