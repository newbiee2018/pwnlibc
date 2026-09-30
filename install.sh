#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GLIBC_DIR="${PWNLIBC_DIR:-/glibc}"

echo "=== pwnlibc installer ==="
echo ""

# --- Glibc directory ---
echo "[1/2] Setting up glibc directory ($GLIBC_DIR)..."
if [ -d "$GLIBC_DIR" ] && [ -w "$GLIBC_DIR" ]; then
    echo "  $GLIBC_DIR exists and is writable."
else
    echo "  Need root to create/fix $GLIBC_DIR."
    echo "  (This is the only step that requires sudo.)"
    sudo mkdir -p "$GLIBC_DIR"
    sudo chown "$(id -u):$(id -g)" "$GLIBC_DIR"
    echo "  Created $GLIBC_DIR (owned by $(whoami))."
fi

# --- Install the pwnlibc command ---
echo ""
echo "[2/2] Installing the pwnlibc command..."

if command -v pipx >/dev/null 2>&1; then
    # Remove the legacy wrapper from older install.sh runs — it would shadow
    # the pipx-provided console script in ~/.local/bin.
    LEGACY="$HOME/.local/bin/pwnlibc"
    if [ -f "$LEGACY" ] && grep -q "python3 -m pwnlibc" "$LEGACY" 2>/dev/null; then
        rm -f "$LEGACY"
        echo "  Removed legacy wrapper at $LEGACY."
    fi
    # Also drop the legacy .pth path hook if present
    SITE_PACKAGES="$(python3 -c 'import site; print(site.getusersitepackages())')"
    if [ -f "$SITE_PACKAGES/pwnlibc.pth" ]; then
        rm -f "$SITE_PACKAGES/pwnlibc.pth"
        echo "  Removed legacy path hook at $SITE_PACKAGES/pwnlibc.pth."
    fi

    # --editable: the command always runs this checkout, so git pull / edits
    # apply without reinstalling. Idempotent: reinstall falls back to upgrade.
    if pipx install --editable "$SCRIPT_DIR" >/dev/null 2>&1; then
        echo "  Installed via pipx (editable, from $SCRIPT_DIR)."
    else
        pipx upgrade pwnlibc >/dev/null 2>&1 || pipx install --editable --force "$SCRIPT_DIR" >/dev/null 2>&1
        echo "  Already installed via pipx — refreshed."
    fi
    pipx ensurepath >/dev/null 2>&1 || true
else
    echo "  pipx not found — falling back to the legacy method."
    echo "  (Recommended instead: sudo apt install pipx, then re-run this script.)"
    echo ""

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
fi

# Verify
echo ""
if command -v pwnlibc >/dev/null 2>&1 && pwnlibc --help >/dev/null 2>&1; then
    echo "=== Install complete ==="
    echo ""
    echo "Usage:    pwnlibc --help"
    echo "Glibc dir: $GLIBC_DIR"
    echo "Update:   git pull (editable install picks it up automatically)"
    echo "Remove:   pipx uninstall pwnlibc"
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) ;;
        *) echo ""
           echo "NOTE: Add ~/.local/bin to your PATH if not already:"
           echo "  pipx ensurepath" ;;
    esac
else
    echo "=== Install failed ==="
    echo "Try: python3 -m pwnlibc --help"
    exit 1
fi
