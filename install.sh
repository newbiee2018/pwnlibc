#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

pip3 install -r "$SCRIPT_DIR/requirements.txt"

WRAPPER="/usr/local/bin/pwnlibc"
cat > /tmp/pwnlibc_wrapper <<EOF
#!/bin/bash
exec python3 -m pwnlibc "\$@"
EOF

sudo install -m 755 /tmp/pwnlibc_wrapper "$WRAPPER"
rm /tmp/pwnlibc_wrapper

# Add the package to Python's path
SITE_PACKAGES="$(python3 -c 'import site; print(site.getusersitepackages())')"
mkdir -p "$SITE_PACKAGES"
PTH_FILE="$SITE_PACKAGES/pwnlibc.pth"
echo "$SCRIPT_DIR" > "$PTH_FILE"

echo "Installed pwnlibc to $WRAPPER"
echo "Python path entry: $PTH_FILE"
echo "Usage: pwnlibc --help"
