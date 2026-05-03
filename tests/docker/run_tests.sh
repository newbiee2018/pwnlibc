#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

TARGETS="${@:-ubuntu1804 ubuntu2004 ubuntu2204 ubuntu2404 ubuntu2604}"

PASS=()
FAIL=()
SYNTAX_FAIL=()

for target in $TARGETS; do
    echo ""
    echo "============================================"
    echo "  Building and testing: $target"
    echo "============================================"
    echo ""

    if ! docker compose build "$target" 2>&1; then
        echo "BUILD FAILED: $target"
        FAIL+=("$target (build)")
        continue
    fi

    echo ""
    echo "--- Running tests on $target ---"
    echo ""

    if docker compose run --rm "$target" 2>&1; then
        PASS+=("$target")
    else
        exit_code=$?
        # Check if it's a syntax error (Python version incompatibility)
        output=$(docker compose run --rm "$target" python3 -c "import pwnlibc" 2>&1 || true)
        if echo "$output" | grep -qE "SyntaxError|TypeError.*subscript"; then
            SYNTAX_FAIL+=("$target")
            echo "SYNTAX INCOMPATIBLE: $target (expected for older Python)"
        else
            FAIL+=("$target")
        fi
    fi
done

echo ""
echo "============================================"
echo "  TEST SUMMARY"
echo "============================================"

if [ ${#PASS[@]} -gt 0 ]; then
    echo "  PASS: ${PASS[*]}"
fi
if [ ${#SYNTAX_FAIL[@]} -gt 0 ]; then
    echo "  SYNTAX INCOMPATIBLE (expected): ${SYNTAX_FAIL[*]}"
fi
if [ ${#FAIL[@]} -gt 0 ]; then
    echo "  FAIL: ${FAIL[*]}"
fi
echo "============================================"

if [ ${#FAIL[@]} -gt 0 ]; then
    exit 1
fi
