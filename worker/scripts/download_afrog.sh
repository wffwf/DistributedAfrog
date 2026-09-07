#!/usr/bin/env bash
set -e

AFROG_BIN="${AFROG_BIN:-/app/afrog-bin/afrog}"
DIR="$(dirname "$AFROG_BIN")"
VERSION="${AFROG_VERSION:-latest}"
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64) GOARCH="amd64" ;;
    aarch64|arm64) GOARCH="arm64" ;;
    *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac

if [ -x "$AFROG_BIN" ]; then
    echo "afrog already exists at $AFROG_BIN"
    exit 0
fi

mkdir -p "$DIR"

if [ "$VERSION" = "latest" ]; then
    ASSET_URL="$(curl -fsSL https://api.github.com/repos/zan8in/afrog/releases/latest | grep -oE '"browser_download_url": *"[^"]*linux_'"$GOARCH"'\.zip"' | head -1 | sed -E 's/.*"browser_download_url": *"([^"]*)"/\1/')"
    if [ -z "$ASSET_URL" ]; then
        echo "failed to resolve latest asset url" >&2
        exit 1
    fi
    echo "resolved: $ASSET_URL"
else
    ASSET_URL="https://github.com/zan8in/afrog/releases/download/${VERSION}/afrog_${VERSION#v}_linux_${GOARCH}.zip"
fi

TMP="$(mktemp -d)"
echo "downloading afrog ..."
curl -fL "$ASSET_URL" -o "$TMP/afrog.zip"
unzip -o "$TMP/afrog.zip" -d "$TMP" >/dev/null
BIN="$(find "$TMP" -type f -perm -u+x | head -1 || find "$TMP" -type f -name 'afrog*' | head -1)"
if [ -z "$BIN" ]; then
    echo "no binary found in archive" >&2
    exit 1
fi
chmod +x "$BIN"
cp "$BIN" "$AFROG_BIN"
rm -rf "$TMP"
echo "afrog installed at $AFROG_BIN"
"$AFROG_BIN" -h >/dev/null 2>&1 || echo "warn: afrog -h failed"
