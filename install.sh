#!/bin/sh
# logr installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/senaraufi/Security-Log-Analyser/master/install.sh | sh
#
# Optional environment variables:
#   LOGR_VERSION   Install a specific tag (e.g. v1.0.1). Default: latest release.
#   LOGR_BIN_DIR   Install directory. Default: /usr/local/bin (falls back to ~/.local/bin).

set -eu

REPO="senaraufi/Security-Log-Analyser"
BIN_NAME="logr"

err() {
  echo "error: $*" >&2
  exit 1
}

# --- Detect OS/arch --------------------------------------------------------
os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
  Linux)  os_target="unknown-linux-gnu" ;;
  Darwin) os_target="apple-darwin" ;;
  *) err "unsupported OS: $os (use the Windows .zip from the Releases page)" ;;
esac

case "$arch" in
  x86_64 | amd64) arch_target="x86_64" ;;
  arm64 | aarch64)
    if [ "$os" = "Darwin" ]; then
      arch_target="aarch64"
    else
      err "unsupported architecture: $arch on $os (only x86_64 Linux binaries are published)"
    fi
    ;;
  *) err "unsupported architecture: $arch" ;;
esac

target="${arch_target}-${os_target}"

# --- Resolve version -------------------------------------------------------
version="${LOGR_VERSION:-}"
if [ -z "$version" ]; then
  version="$(
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
      | grep '"tag_name":' \
      | head -n1 \
      | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
  )"
  [ -n "$version" ] || err "could not determine latest release version"
fi

asset="${BIN_NAME}-${version}-${target}.tar.gz"
url="https://github.com/${REPO}/releases/download/${version}/${asset}"

echo "Installing ${BIN_NAME} ${version} (${target})..."

# --- Download & extract ----------------------------------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fSL "$url" -o "${tmp}/${asset}" \
  || err "download failed: ${url}"

tar -xzf "${tmp}/${asset}" -C "$tmp" \
  || err "failed to extract ${asset}"

extracted_bin="${tmp}/${BIN_NAME}-${version}-${target}/${BIN_NAME}"
[ -f "$extracted_bin" ] || err "binary not found in archive"
chmod +x "$extracted_bin"

# --- Install ---------------------------------------------------------------
bin_dir="${LOGR_BIN_DIR:-/usr/local/bin}"
if [ ! -d "$bin_dir" ] || [ ! -w "$bin_dir" ]; then
  # Try with sudo for the default system path; otherwise fall back to ~/.local/bin
  if [ "$bin_dir" = "/usr/local/bin" ] && command -v sudo >/dev/null 2>&1; then
    echo "Installing to ${bin_dir} (requires sudo)..."
    sudo mkdir -p "$bin_dir"
    sudo mv "$extracted_bin" "${bin_dir}/${BIN_NAME}"
  else
    bin_dir="${HOME}/.local/bin"
    mkdir -p "$bin_dir"
    mv "$extracted_bin" "${bin_dir}/${BIN_NAME}"
  fi
else
  mv "$extracted_bin" "${bin_dir}/${BIN_NAME}"
fi

echo ""
echo "Installed ${BIN_NAME} to ${bin_dir}/${BIN_NAME}"
case ":${PATH}:" in
  *":${bin_dir}:"*) ;;
  *) echo "Note: ${bin_dir} is not on your PATH. Add it with:"
     echo "  export PATH=\"${bin_dir}:\$PATH\"" ;;
esac
echo "Run '${BIN_NAME} --help' to get started."
