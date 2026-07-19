#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$ROOT/build"
APP_NAME="Enclave"
CLI_BIN="$BUILD_DIR/enclave-cli"
APP_BIN="$BUILD_DIR/$APP_NAME"
APP_BUNDLE="$ROOT/$APP_NAME.app"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

mkdir -p "$BUILD_DIR"

CARGON2_DIR="$ROOT/Sources/CArgon2"
CARGON2_INC="$CARGON2_DIR/include"
CARGON2_OBJ="$BUILD_DIR/argon2.o"

echo "Compiling Argon2id backend..."
clang -O2 -fno-strict-aliasing -c "$CARGON2_DIR/argon2.c" \
  -I "$CARGON2_INC" \
  -o "$CARGON2_OBJ"

echo "Building Enclave CLI..."
swiftc -O \
  -framework Foundation \
  -framework CryptoKit \
  -framework Security \
  "$ROOT/Sources/EnclaveCrypto.swift" \
  "$ROOT/Sources/EnclaveIO.swift" \
  "$ROOT/Sources/EnclaveFolder.swift" \
  "$ROOT/Sources/cli_main.swift" \
  -I "$CARGON2_INC" \
  "$CARGON2_OBJ" \
  -o "$CLI_BIN"

echo "Building Enclave app..."
swiftc -O \
  -framework AppKit \
  -framework Foundation \
  -framework CryptoKit \
  -framework Security \
  -framework UniformTypeIdentifiers \
  -framework WebKit \
  "$ROOT/Sources/EnclaveCrypto.swift" \
  "$ROOT/Sources/EnclaveIO.swift" \
  "$ROOT/Sources/EnclaveFolder.swift" \
  "$ROOT/Sources/AppInfo.swift" \
  "$ROOT/Sources/Theme.swift" \
  "$ROOT/Sources/FileDropView.swift" \
  "$ROOT/Sources/HelpWindowController.swift" \
  "$ROOT/Sources/MainWindowController.swift" \
  "$ROOT/Sources/AppDelegate.swift" \
  "$ROOT/Sources/app_main.swift" \
  -I "$CARGON2_INC" \
  "$CARGON2_OBJ" \
  -o "$APP_BIN"

echo "Running self-test..."
swiftc -O \
  -framework Foundation \
  -framework CryptoKit \
  -framework Security \
  "$ROOT/Sources/EnclaveCrypto.swift" \
  "$ROOT/Sources/EnclaveIO.swift" \
  "$ROOT/Sources/EnclaveFolder.swift" \
  "$ROOT/test_enclave.swift" \
  -I "$CARGON2_INC" \
  "$CARGON2_OBJ" \
  -o "$BUILD_DIR/test_enclave"
"$BUILD_DIR/test_enclave"

echo "Building app bundle..."
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"

cp "$APP_BIN" "$APP_BUNDLE/Contents/MacOS/$APP_NAME"
cp "$ROOT/Resources/Info.plist" "$APP_BUNDLE/Contents/Info.plist"
if [[ ! -d "$ROOT/Resources/Enclave.help" ]]; then
  echo "Missing help bundle: $ROOT/Resources/Enclave.help" >&2
  exit 1
fi
cp -R "$ROOT/Resources/Enclave.help" "$APP_BUNDLE/Contents/Resources/"

# Fill in the help book's version/build placeholders from Info.plist so the help
# window shows real numbers instead of the literal {{VERSION}}/{{BUILD}} tokens.
HELP_INDEX="$APP_BUNDLE/Contents/Resources/Enclave.help/Contents/Resources/en.lproj/index.html"
if [[ -f "$HELP_INDEX" ]]; then
  APP_VERSION="$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$ROOT/Resources/Info.plist")"
  APP_BUILD="$(/usr/libexec/PlistBuddy -c 'Print CFBundleVersion' "$ROOT/Resources/Info.plist")"
  sed -i '' -e "s/{{VERSION}}/$APP_VERSION/g" -e "s/{{BUILD}}/$APP_BUILD/g" "$HELP_INDEX"
fi
chmod +x "$APP_BUNDLE/Contents/MacOS/$APP_NAME"

if command -v sips >/dev/null && command -v iconutil >/dev/null; then
  echo "Generating app icon..."
  swiftc -O \
    -framework AppKit \
    "$ROOT/Resources/make_icon.swift" \
    -o "$BUILD_DIR/make_icon"
  "$BUILD_DIR/make_icon" "$ROOT/Resources/AppIcon.png"

  ICONSET="$BUILD_DIR/AppIcon.iconset"
  rm -rf "$ICONSET"
  mkdir -p "$ICONSET"

  for size in 16 32 128 256 512; do
    sips -z $size $size "$ROOT/Resources/AppIcon.png" --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
    double=$((size * 2))
    sips -z $double $double "$ROOT/Resources/AppIcon.png" --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
  done

  iconutil -c icns "$ICONSET" -o "$APP_BUNDLE/Contents/Resources/AppIcon.icns"
fi

if command -v codesign >/dev/null; then
  codesign --force --deep --sign - "$APP_BUNDLE" >/dev/null
fi

chmod +x "$CLI_BIN"
echo "Built CLI: $CLI_BIN"
echo "Built app: $APP_BUNDLE"

if [[ "${1:-}" == "--install" ]]; then
  echo "Installing CLI to $INSTALL_DIR/enclave"
  mkdir -p "$INSTALL_DIR"
  cp "$CLI_BIN" "$INSTALL_DIR/enclave"
  echo "Installed: $INSTALL_DIR/enclave"
fi