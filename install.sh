#!/bin/sh
# curl -fsSL https://raw.githubusercontent.com/Harsette/ralx/main/install.sh | sh
set -eu
case "$(uname -s)" in Darwin) os=darwin;; Linux) os=linux;; *) echo 'Unsupported OS' >&2; exit 1;; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64;; arm64|aarch64) arch=arm64;; *) echo 'Unsupported architecture' >&2; exit 1;; esac
asset="ralx_${os}_${arch}"
release=${RALX_RELEASE_BASE_URL:-https://github.com/Harsette/ralx/releases/latest/download}
if [ -n "${RALX_VERSION:-}" ] && [ -z "${RALX_RELEASE_BASE_URL:-}" ]; then release="https://github.com/Harsette/ralx/releases/download/$RALX_VERSION"; fi
bin=${RALX_INSTALL_DIR:-$HOME/.local/bin}
case "$bin" in /*) ;; *) echo 'RALX_INSTALL_DIR must be absolute' >&2; exit 1;; esac
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
curl -fLsS "${release%/}/$asset" -o "$tmp/$asset"
curl -fLsS "${release%/}/checksums.txt" -o "$tmp/checksums.txt"
expected=$(awk -v n="$asset" '$2==n || $2=="*"n { print $1 }' "$tmp/checksums.txt")
[ "${#expected}" -eq 64 ] || { echo 'Missing or duplicate checksum' >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum "$tmp/$asset" | awk '{print $1}'); else actual=$(shasum -a 256 "$tmp/$asset" | awk '{print $1}'); fi
[ "$expected" = "$actual" ] || { echo 'The download check failed. Nothing was installed.' >&2; exit 1; }
chmod 755 "$tmp/$asset"
upgrade=$("$tmp/$asset" install-upgrade --target "$bin/ralx") || { printf '%s\n' "$upgrade" >&2; exit 1; }
if [ "$upgrade" != fresh ]; then printf '%s\n' "$upgrade"; exit 0; fi
mkdir -p "$bin" "$HOME/.ralx"
mv "$tmp/$asset" "$bin/ralx"
if [ "$os" = darwin ] && command -v xattr >/dev/null 2>&1; then
  if xattr -p com.apple.quarantine "$bin/ralx" >/dev/null 2>&1; then
    xattr -d com.apple.quarantine "$bin/ralx"
    echo 'Removed the download quarantine flag from RalX.'
  fi
fi
export PATH="$bin:$PATH"
# The binary writes a JSON receipt and shell PATH entry with proper escaping.
"$bin/ralx" install-path
echo "Checked the download. Installed $bin/ralx"
if [ "$#" -gt 0 ]; then "$bin/ralx" setup "$@"
elif [ "${RALX_SETUP_YES:-}" = 1 ]; then "$bin/ralx" setup --mode local --clients all --yes
elif [ -t 0 ]; then "$bin/ralx" setup
elif [ -r /dev/tty ]; then "$bin/ralx" setup </dev/tty
else echo 'Run ralx setup from a terminal, or set RALX_SETUP_YES=1.' >&2; exit 1
fi

"$bin/ralx" doctor
