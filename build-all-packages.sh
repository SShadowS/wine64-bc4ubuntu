#!/bin/bash
# Build all package variants (tarball + .deb for different distributions)

set -e

STAGING_DIR="${STAGING_DIR:-/staging}"
OUTPUT_DIR="${OUTPUT_DIR:-/output}"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║      Wine Custom Build - Multi-Package Builder                ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Get version
if [ -f "$STAGING_DIR/usr/local/share/wine/wine-version.txt" ]; then
    WINE_VERSION=$(cat "$STAGING_DIR/usr/local/share/wine/wine-version.txt" | sed 's/wine-//')
else
    echo "ERROR: Wine version file not found"
    exit 1
fi

if [ -d "/wine-src/.git" ]; then
    GIT_DESC=$(cd /wine-src && git describe --always --dirty 2>/dev/null || echo "unknown")
    VERSION="${WINE_VERSION}-${GIT_DESC}"
else
    VERSION="${WINE_VERSION}"
fi

echo "Version: $VERSION"
echo "Staging: $STAGING_DIR"
echo "Output: $OUTPUT_DIR"
echo ""

# 1. Build generic tarball (already done by main script)
echo "═══ 1. Generic Tarball ═══"
if [ -f "$OUTPUT_DIR/wine-custom-${VERSION}.tar.gz" ]; then
    echo "✓ Tarball already exists"
else
    echo "  Tarball will be created by main build script"
fi
echo ""

# 2. Build .deb for Ubuntu 22.04 (Jammy)
echo "═══ 2. .deb for Ubuntu 22.04 (Jammy) ═══"
if [ -f "/wine-src/build-deb.sh" ]; then
    /wine-src/build-deb.sh
    echo "✓ Ubuntu 22.04 .deb package created"
else
    echo "ERROR: build-deb.sh not found"
    exit 1
fi
echo ""

# 3. Create a PPA-compatible source package (optional, for future)
echo "═══ 3. Source Package (for PPA upload) ═══"
echo "  (Future enhancement - manual PPA upload for now)"
echo ""

# Summary
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                All Packages Built Successfully                ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "Built packages:"
echo ""

for file in "$OUTPUT_DIR"/*; do
    if [ -f "$file" ]; then
        SIZE=$(du -h "$file" | cut -f1)
        echo "  $(basename $file) - $SIZE"
    fi
done

echo ""
echo "Distribution compatibility:"
echo "  • Tarball: All Linux distributions (generic)"
echo "  • .deb:    Ubuntu 22.04+, Debian 11+, Linux Mint 21+"
echo ""

exit 0
