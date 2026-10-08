#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== pwnlibc installer ==="
echo ""

# --- Glibc data directory ---
# OpenSSL-style prompt: Enter accepts the default; the choice is persisted to
# ~/.config/pwnlibc/glibc_dir and picked up by the CLI ($PWNLIBC_DIR still
# overrides). Setting PWNLIBC_DIR beforehand makes this step non-interactive.
echo "[1/2] Glibc data directory (where glibc versions are stored)"

DEFAULT_DIR="$HOME/.local/share/pwnlibc"
if [ -n "$(ls -A /glibc 2>/dev/null)" ]; then
    DEFAULT_DIR="/glibc"
    echo "  Existing install detected at /glibc — it stays the default."
    echo "  Enter a different path to switch (move /glibc's contents yourself),"
    echo "  or press Enter to keep using it."
fi

if [ -n "${PWNLIBC_DIR:-}" ]; then
    GLIBC_DIR="$PWNLIBC_DIR"
    echo "  Using \$PWNLIBC_DIR: $GLIBC_DIR"
else
    read -r -e -p "Glibc directory [${DEFAULT_DIR}]: " INPUT_DIR || INPUT_DIR=""
    GLIBC_DIR="${INPUT_DIR:-$DEFAULT_DIR}"
    GLIBC_DIR="${GLIBC_DIR/#\~/$HOME}"   # expand a leading ~
fi

if [ -d "$GLIBC_DIR" ] && [ -w "$GLIBC_DIR" ]; then
    echo "  $GLIBC_DIR exists and is writable."
else
    if mkdir -p "$GLIBC_DIR" 2>/dev/null; then
        echo "  Created $GLIBC_DIR."
    else
        echo "  Need root to create $GLIBC_DIR."
        echo "  (The only step that may require sudo.)"
        sudo mkdir -p "$GLIBC_DIR"
        sudo chown "$(id -u):$(id -g)" "$GLIBC_DIR"
        echo "  Created $GLIBC_DIR (owned by $(whoami))."
    fi
fi

CONFIG_DIR_HOME="$HOME/.config/pwnlibc"
mkdir -p "$CONFIG_DIR_HOME"
printf '%s\n' "$GLIBC_DIR" > "$CONFIG_DIR_HOME/glibc_dir"
echo "  Saved as default in $CONFIG_DIR_HOME/glibc_dir"

# --- Install the pwnlibc command ---
echo ""
echo "[2/2] Installing the pwnlibc command..."

# Clean up artifacts from pre-pipx install.sh runs: the wrapper would shadow
# the pip/pipx-provided console script, and the .pth hook double-imports.
LEGACY="$HOME/.local/bin/pwnlibc"
if [ -f "$LEGACY" ] && grep -q "python3 -m pwnlibc" "$LEGACY" 2>/dev/null; then
    rm -f "$LEGACY"
    echo "  Removed legacy wrapper at $LEGACY."
fi
SITE_PACKAGES="$(python3 -c 'import site; print(site.getusersitepackages())')"
if [ -f "$SITE_PACKAGES/pwnlibc.pth" ]; then
    rm -f "$SITE_PACKAGES/pwnlibc.pth"
    echo "  Removed legacy path hook at $SITE_PACKAGES/pwnlibc.pth."
fi

# Legacy no-pip method: apt deps + .pth path hook + shell wrapper.
install_legacy() {
    if python3 -c "import click, rich" 2>/dev/null; then
        echo "  click and rich already available."
    else
        echo "  Installing dependencies via apt (needs sudo)..."
        sudo apt install -y python3-click python3-rich
    fi
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
}

if command -v pipx >/dev/null 2>&1; then
    # --editable: the command always runs this checkout, so git pull / edits
    # apply without reinstalling. Idempotent: reinstall falls back to upgrade.
    if pipx install --editable "$SCRIPT_DIR" >/dev/null 2>&1; then
        echo "  Installed via pipx (editable, from $SCRIPT_DIR)."
    else
        pipx upgrade pwnlibc >/dev/null 2>&1 || pipx install --editable --force "$SCRIPT_DIR" >/dev/null 2>&1
        echo "  Already installed via pipx — refreshed."
    fi
    pipx ensurepath >/dev/null 2>&1 || true
elif python3 -m pip --version >/dev/null 2>&1; then
    # No pipx: plain pip --user. Also editable for the same auto-update
    # behaviour. Newer Debian/Ubuntu refuses user installs under PEP 668
    # unless --break-system-packages is given — and the flag must come
    # BEFORE --editable, which consumes the next token as its value.
    echo "  pipx not found — installing with pip --user."
    echo "  (Recommended for isolation: sudo apt install pipx, then re-run.)"
    if python3 -m pip install -q --user --editable "$SCRIPT_DIR" 2>/dev/null; then
        echo "  Installed via pip --user (editable, from $SCRIPT_DIR)."
    elif python3 -m pip install -q --user --break-system-packages --editable "$SCRIPT_DIR" 2>/dev/null; then
        echo "  Installed via pip --user (editable, --break-system-packages)."
    else
        echo "  pip install failed — falling back to the legacy method."
        install_legacy
    fi
    echo "  Command installed at $HOME/.local/bin/pwnlibc"
else
    echo "  Neither pipx nor pip found — using the legacy method."
    install_legacy
fi

# Verify (the command may not be on this shell's PATH yet on first install)
echo ""
BIN=""
if command -v pwnlibc >/dev/null 2>&1; then
    BIN="pwnlibc"
elif [ -x "$HOME/.local/bin/pwnlibc" ]; then
    BIN="$HOME/.local/bin/pwnlibc"
fi
if [ -n "$BIN" ] && "$BIN" --help >/dev/null 2>&1; then
    echo "=== Install complete ==="
    echo ""
    echo "Usage:    pwnlibc --help"
    echo "Glibc dir: $GLIBC_DIR"
    echo "Update:   git pull (editable install picks it up automatically)"
    echo "Remove:   pipx uninstall pwnlibc  (or: python3 -m pip uninstall pwnlibc)"
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) ;;
        *) echo ""
           echo "NOTE: $HOME/.local/bin is not on your PATH for this shell."
           echo "  Add it:  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc"
           echo "  (or run: pipx ensurepath)" ;;
    esac
else
    echo "=== Install failed ==="
    echo "Try: python3 -m pwnlibc --help"
    exit 1
fi
