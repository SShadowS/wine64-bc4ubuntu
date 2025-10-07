#!/bin/bash
# Verify Wine library configuration matches reference build
# This ensures container builds have same library support as host

set -e

# Use C locale for consistent sorting
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${1:-/wine-build}"
REFERENCE_64="${SCRIPT_DIR}/reference-libs-64.txt"
REFERENCE_32="${SCRIPT_DIR}/reference-libs-32.txt"

echo "============================================"
echo "Wine Library Configuration Verification"
echo "============================================"
echo "Build directory: $BUILD_DIR"
echo ""

# Function to extract detected libraries from config.log
extract_libs() {
    local config_log="$1"
    if [ ! -f "$config_log" ]; then
        echo ""
        return 1
    fi
    grep '^ac_cv_lib_soname_' "$config_log" | grep -v "=$" | grep -v "=''" | cut -d= -f1 | sed 's/ac_cv_lib_soname_//' | sort
}

# Function to verify architecture
verify_arch() {
    local arch="$1"
    local reference_file="$2"
    local config_log="$BUILD_DIR/$arch/config.log"

    echo "---------------------------------------------------"
    echo "Verifying: $arch"
    echo "---------------------------------------------------"

    if [ ! -f "$config_log" ]; then
        echo "❌ ERROR: Config log not found: $config_log"
        return 1
    fi

    if [ ! -f "$reference_file" ]; then
        echo "⚠️  WARNING: Reference file not found: $reference_file"
        echo "   Generating from current build..."
        extract_libs "$config_log" > "$reference_file"
        echo "✓ Reference saved to: $reference_file"
        echo ""
        return 0
    fi

    # Extract current build libraries
    local current_libs=$(mktemp)
    extract_libs "$config_log" > "$current_libs"

    # Compare with reference
    local missing=$(comm -23 "$reference_file" "$current_libs" || true)
    local extra=$(comm -13 "$reference_file" "$current_libs" || true)
    local missing_count=0
    local extra_count=0
    [ -n "$missing" ] && missing_count=$(echo "$missing" | wc -l)
    [ -n "$extra" ] && extra_count=$(echo "$extra" | wc -l)
    local total_ref=$(wc -l < "$reference_file")
    local total_current=$(wc -l < "$current_libs")

    echo "Reference libraries: $total_ref"
    echo "Current libraries:   $total_current"
    echo ""

    local errors=0

    if [ "$missing_count" -gt 0 ]; then
        echo "❌ MISSING Libraries ($missing_count):"
        echo "$missing" | while read lib; do
            if [ -n "$lib" ]; then
                # Get the SONAME from reference build
                soname=$(grep "^ac_cv_lib_soname_$lib=" "$BUILD_DIR/$arch/config.log" 2>/dev/null | cut -d= -f2 || echo "")
                echo "  - $lib${soname:+ (expected: $soname)}"
            fi
        done
        echo ""
        errors=$((errors + 1))
    fi

    if [ "$extra_count" -gt 0 ]; then
        echo "ℹ️  EXTRA Libraries ($extra_count - not in reference):"
        echo "$extra" | while read lib; do
            if [ -n "$lib" ]; then
                echo "  + $lib"
            fi
        done
        echo ""
    fi

    if [ "$missing_count" -eq 0 ] && [ "$extra_count" -eq 0 ]; then
        echo "✓ All reference libraries detected correctly"
        echo ""
    fi

    rm -f "$current_libs"
    return $errors
}

# Verify both architectures
errors=0

verify_arch "wine-64" "$REFERENCE_64" || errors=$((errors + 1))
verify_arch "wine-32" "$REFERENCE_32" || errors=$((errors + 1))

echo "============================================"

if [ $errors -gt 0 ]; then
    echo "❌ VERIFICATION FAILED"
    echo ""
    echo "The container build is missing libraries that are present"
    echo "in the reference build. This means:"
    echo ""
    echo "  1. Some Wine features will not work correctly"
    echo "  2. Applications may fail with missing functionality"
    echo "  3. Build dependencies are incomplete"
    echo ""
    echo "To fix:"
    echo "  - Compare Dockerfile package lists with host system"
    echo "  - Install missing -dev packages before Wine configure"
    echo "  - Ensure runtime libraries are not removed during cleanup"
    echo ""
    exit 1
else
    echo "✓ VERIFICATION PASSED"
    echo ""
    echo "All reference libraries detected in both 32-bit and 64-bit builds."
    echo "Wine build matches reference configuration."
fi

echo "============================================"
