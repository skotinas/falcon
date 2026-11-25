#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN_SRC="$REPO_DIR/target/release/falcon"
APP_OUT="${1:-/Users/spiros/Desktop/Falcon.app}"

if [[ ! -x "$BIN_SRC" ]]; then
  echo "ERROR: release binary not found at $BIN_SRC (run 'cargo build --release' first)" >&2
  exit 1
fi

rm -rf "$APP_OUT"
mkdir -p "$APP_OUT/Contents/MacOS" "$APP_OUT/Contents/Resources"

cp "$BIN_SRC" "$APP_OUT/Contents/MacOS/falcon"
chmod 755 "$APP_OUT/Contents/MacOS/falcon"

cat > "$APP_OUT/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleDisplayName</key>
    <string>Falcon</string>
    <key>CFBundleExecutable</key>
    <string>falcon-launcher</string>
    <key>CFBundleIconFile</key>
    <string>falcon</string>
    <key>CFBundleIdentifier</key>
    <string>io.falcon.comsec</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>Falcon</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>0.4.0</string>
    <key>CFBundleVersion</key>
    <string>4</string>
    <key>LSMinimumSystemVersion</key>
    <string>12.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
PLIST

cat > "$APP_OUT/Contents/MacOS/falcon-launcher" <<'LAUNCHER'
#!/usr/bin/env bash
set -euo pipefail

APP_MACOS_DIR="$(cd "$(dirname "$0")" && pwd)"
FALCON_BIN="$APP_MACOS_DIR/falcon"
STATE_DIR="$HOME/Library/Application Support/Falcon"
LOG_DIR="$HOME/Library/Logs"
PID_FILE="$STATE_DIR/ui.pid"
URL_FILE="$STATE_DIR/ui.url"
LOG_FILE="$LOG_DIR/falcon-ui.log"

mkdir -p "$STATE_DIR" "$LOG_DIR"
chmod 700 "$STATE_DIR"

alert_fail() {
  local msg="$1"
  /usr/bin/osascript -e "display dialog \"Falcon COMSEC Error: $msg\" buttons {\"OK\"} default button 1 with icon stop with title \"Falcon\"" >/dev/null 2>&1 || true
  exit 1
}

# 1. Fail-closed FIPS 140-3 Power-On Self-Test before starting or opening UI
if ! "$FALCON_BIN" post >/dev/null 2>&1; then
  alert_fail "FIPS 140-3 Power-On Self-Test (POST) FAILED. Halting."
fi

# 2. Reuse already-running Falcon UI instance if still alive
if [[ -f "$PID_FILE" && -f "$URL_FILE" ]]; then
  OLD_PID="$(cat "$PID_FILE" 2>/dev/null || true)"
  OLD_URL="$(cat "$URL_FILE" 2>/dev/null || true)"
  if [[ -n "$OLD_PID" && -n "$OLD_URL" ]] && kill -0 "$OLD_PID" 2>/dev/null; then
    open "$OLD_URL"
    exit 0
  fi
fi

# 3. Start Falcon UI on loopback with automatic port fallback (7842..7852)
umask 077
URL=""
STARTED_PID=""
for PORT in 7842 7843 7844 7845 7846 7847 7848 7849 7850 7851 7852; do
  : > "$LOG_FILE"
  chmod 600 "$LOG_FILE"
  nohup "$FALCON_BIN" ui --port "$PORT" --auto-lock-mins 15 >"$LOG_FILE" 2>&1 </dev/null &
  CAND_PID=$!

  for _ in $(seq 1 40); do
    if ! kill -0 "$CAND_PID" 2>/dev/null; then
      break
    fi
    FOUND="$(grep -m1 '^Open URL: ' "$LOG_FILE" 2>/dev/null | sed 's/^Open URL: //' || true)"
    if [[ -n "$FOUND" ]]; then
      URL="$FOUND"
      STARTED_PID="$CAND_PID"
      break
    fi
    sleep 0.1
  done

  if [[ -n "$URL" ]]; then
    break
  fi
  kill "$CAND_PID" 2>/dev/null || true
done

if [[ -z "$URL" || -z "$STARTED_PID" ]]; then
  alert_fail "Could not start local Falcon console on loopback ports 7842-7852."
fi

printf '%s\n' "$STARTED_PID" > "$PID_FILE"
printf '%s\n' "$URL" > "$URL_FILE"
chmod 600 "$PID_FILE" "$URL_FILE"

open "$URL"
LAUNCHER
chmod 755 "$APP_OUT/Contents/MacOS/falcon-launcher"

# Generate tactical multi-res macOS .icns icon directly from master Falcon SVG
TMP_ICON_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_ICON_DIR"' EXIT
ICONSET="$TMP_ICON_DIR/falcon.iconset"
mkdir -p "$ICONSET"

qlmanage -t -s 1024 -o "$TMP_ICON_DIR" "$REPO_DIR/crates/falcon-cli/assets/favicon.svg" >/dev/null 2>&1
BASE_PNG="$TMP_ICON_DIR/favicon.svg.png"

for sz in 16 32 128 256 512; do
  sips -z "$sz" "$sz" "$BASE_PNG" --out "$ICONSET/icon_${sz}x${sz}.png" >/dev/null
  sz2=$((sz * 2))
  sips -z "$sz2" "$sz2" "$BASE_PNG" --out "$ICONSET/icon_${sz}x${sz}@2x.png" >/dev/null
done

iconutil -c icns "$ICONSET" -o "$APP_OUT/Contents/Resources/falcon.icns"
plutil -lint "$APP_OUT/Contents/Info.plist"
echo "Built macOS desktop bundle: $APP_OUT"
