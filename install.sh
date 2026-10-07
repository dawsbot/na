#!/bin/sh
# Installs the latest release of na (https://github.com/dawsbot/na).
#
#   curl -fsSL https://raw.githubusercontent.com/dawsbot/na/main/install.sh | sh
#
# Options (environment variables):
#   NA_INSTALL_DIR  where to put the binary (default: /usr/local/bin if writable,
#                   otherwise ~/.local/bin)
#   NA_VERSION      release tag to install, e.g. v0.2.0 (default: latest)
set -eu

REPO="dawsbot/na"
BIN="na"

say() { printf '%s\n' "$*" >&2; }
fail() { say "install.sh: $*"; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || fail "'$1' is required but not found"; }
need curl
need tar

os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Darwin)
    case "$arch" in
      arm64|aarch64) target="aarch64-apple-darwin" ;;
      x86_64)        target="x86_64-apple-darwin" ;;
      *) fail "unsupported macOS architecture: $arch" ;;
    esac ;;
  Linux)
    case "$arch" in
      x86_64|amd64)  target="x86_64-unknown-linux-musl" ;;
      aarch64|arm64) target="aarch64-unknown-linux-musl" ;;
      *) fail "unsupported Linux architecture: $arch" ;;
    esac ;;
  MINGW*|MSYS*|CYGWIN*)
    case "$arch" in
      x86_64) target="x86_64-pc-windows-msvc" ;;
      *) fail "unsupported Windows architecture: $arch" ;;
    esac ;;
  *) fail "unsupported OS: $os (build from source: cargo install --git https://github.com/$REPO)" ;;
esac

case "$target" in
  *windows*) asset="$BIN-$target.zip"; need unzip ;;
  *)         asset="$BIN-$target.tar.gz" ;;
esac

version="${NA_VERSION:-latest}"
if [ "$version" = "latest" ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$version"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "Downloading $asset ($version)..."
if ! curl -fsSL --retry 3 -o "$tmp/$asset" "$base/$asset"; then
  fail "no prebuilt binary found at $base/$asset
Build from source instead (needs Rust 1.80+ via https://rustup.rs):
  cargo install --git https://github.com/$REPO"
fi
curl -fsSL --retry 3 -o "$tmp/checksums.txt" "$base/checksums.txt" || fail "could not download checksums.txt"

expected="$(grep " $asset\$" "$tmp/checksums.txt" | cut -d' ' -f1)"
[ -n "$expected" ] || fail "no checksum listed for $asset"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$asset" | cut -d' ' -f1)"
else
  actual="$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1)"
fi
[ "$actual" = "$expected" ] || fail "checksum mismatch for $asset (expected $expected, got $actual)"

case "$asset" in
  *.zip) (cd "$tmp" && unzip -q "$asset"); exe="$tmp/$BIN.exe" ;;
  *)     tar -xzf "$tmp/$asset" -C "$tmp"; exe="$tmp/$BIN" ;;
esac
[ -f "$exe" ] || fail "archive did not contain $BIN"
chmod +x "$exe"

if [ -n "${NA_INSTALL_DIR:-}" ]; then
  dir="$NA_INSTALL_DIR"
elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
  dir=/usr/local/bin
else
  dir="$HOME/.local/bin"
fi
mkdir -p "$dir"
dest="$dir/$(basename "$exe")"
mv -f "$exe" "$dest"

say "Installed $("$dest" --version) to $dest"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) say "Note: $dir is not on your PATH. Add it, e.g.:  export PATH=\"$dir:\$PATH\"" ;;
esac
