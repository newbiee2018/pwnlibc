#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GLIBC_DIR="${PWNLIBC_DIR:-/glibc}"

echo "=== pwnlibc installer ==="
echo ""

# --- Python dependencies ---
echo "[1/3] Installing Python dependencies..."
if python3 -c "import click, rich" 2>/dev/null; then
    echo "  click and rich already available."
elif pip3 install --user -r "$SCRIPT_DIR/requirements.txt" 2>/dev/null; then
    echo "  Installed via pip3 --user."
elif pip3 install -r "$SCRIPT_DIR/requirements.txt" 2>/dev/null; then
    echo "  Installed via pip3."
else
    echo "  pip failed. Trying apt..."
    sudo apt install -y python3-click python3-rich
fi

# --- Glibc directory ---
echo ""
echo "[2/3] Setting up glibc directory ($GLIBC_DIR)..."
if [ -d "$GLIBC_DIR" ] && [ -w "$GLIBC_DIR" ]; then
    echo "  $GLIBC_DIR exists and is writable."
else
    echo "  Need root to create/fix $GLIBC_DIR."
    echo "  (This is the only step that requires sudo.)"
    sudo mkdir -p "$GLIBC_DIR"
    sudo chown "$(id -u):$(id -g)" "$GLIBC_DIR"
    echo "  Created $GLIBC_DIR (owned by $(whoami))."
fi

# --- Wrapper script + Python path ---
echo ""
echo "[3/3] Installing pwnlibc command..."

SITE_PACKAGES="$(python3 -c 'import site; print(site.getusersitepackages())')"
mkdir -p "$SITE_PACKAGES"
echo "$SCRIPT_DIR" > "$SITE_PACKAGES/pwnlibc.pth"

LOCAL_WRAPPER="$HOME/.local/bin/pwnlibc"
mkdir -p "$(dirname "$LOCAL_WRAPPER")"
cat > "$LOCAL_WRAPPER" <<EOF
#!/bin/bash
exec python3 -m pwnlibc "\$@"
EOF
chmod 755 "$LOCAL_WRAPPER"

echo "  Command:     $LOCAL_WRAPPER"
echo "  Python path: $SITE_PACKAGES/pwnlibc.pth"

# Verify
echo ""
if "$LOCAL_WRAPPER" --help >/dev/null 2>&1; then
    echo "=== Install complete ==="
    echo ""
    echo "Usage: pwnlibc --help"
    echo "Glibc dir: $GLIBC_DIR"
    if ! echo "$PATH" | tr ':' '\n' | grep -qx "$HOME/.local/bin"; then
        echo ""
        echo "NOTE: Add ~/.local/bin to your PATH if not already:"
        echo "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc"
    fi
else
    echo "=== Install failed ==="
    echo "Try: python3 -m pwnlibc --help"
    exit 1
fi
