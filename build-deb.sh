#!/bin/bash
# Wine Custom Build - .deb Package Builder
# Creates a Debian package from Wine installation

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Configuration
STAGING_DIR="${STAGING_DIR:-/staging}"
OUTPUT_DIR="${OUTPUT_DIR:-/output}"
PACKAGE_NAME="wine-custom"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║           Wine Custom Build - .deb Package Builder            ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check if staging directory exists
if [ ! -d "$STAGING_DIR" ]; then
    print_error "Staging directory not found: $STAGING_DIR"
    exit 1
fi

# Get Wine version
if [ -f "$STAGING_DIR/usr/local/share/wine/wine-version.txt" ]; then
    WINE_VERSION=$(cat "$STAGING_DIR/usr/local/share/wine/wine-version.txt" | sed 's/wine-//')
else
    print_error "Wine version file not found"
    exit 1
fi

# Get git description for package version
if [ -d "/wine-src/.git" ]; then
    GIT_DESC=$(cd /wine-src && git describe --always --dirty 2>/dev/null || echo "unknown")
    PACKAGE_VERSION="${WINE_VERSION}-${GIT_DESC}"
else
    PACKAGE_VERSION="${WINE_VERSION}"
fi

print_info "Wine version: $WINE_VERSION"
print_info "Package version: $PACKAGE_VERSION"
print_info "Staging directory: $STAGING_DIR"
print_info "Output directory: $OUTPUT_DIR"

# Create package build directory
PKG_BUILD_DIR="/tmp/${PACKAGE_NAME}_${PACKAGE_VERSION}"
print_info "Creating package build directory: $PKG_BUILD_DIR"
rm -rf "$PKG_BUILD_DIR"
mkdir -p "$PKG_BUILD_DIR"

# Copy Wine installation
print_info "Copying Wine installation..."
cp -r "$STAGING_DIR/usr" "$PKG_BUILD_DIR/"

# Create DEBIAN directory
print_info "Creating package metadata..."
mkdir -p "$PKG_BUILD_DIR/DEBIAN"

# Calculate installed size (in KB)
INSTALLED_SIZE=$(du -sk "$PKG_BUILD_DIR/usr" | cut -f1)

# Copy and update control file
if [ -f "/wine-src/debian-package/control" ]; then
    cp /wine-src/debian-package/control "$PKG_BUILD_DIR/DEBIAN/control"
    sed -i "s/VERSION_PLACEHOLDER/$PACKAGE_VERSION/" "$PKG_BUILD_DIR/DEBIAN/control"
    sed -i "s/SIZE_PLACEHOLDER/$INSTALLED_SIZE/" "$PKG_BUILD_DIR/DEBIAN/control"
else
    print_error "Control file not found"
    exit 1
fi

# Copy maintainer scripts
for script in postinst prerm postrm; do
    if [ -f "/wine-src/debian-package/$script" ]; then
        cp "/wine-src/debian-package/$script" "$PKG_BUILD_DIR/DEBIAN/"
        chmod 755 "$PKG_BUILD_DIR/DEBIAN/$script"
        print_info "Added $script script"
    fi
done

# Create documentation directory
print_info "Adding documentation..."
mkdir -p "$PKG_BUILD_DIR/usr/share/doc/$PACKAGE_NAME"

# Copy documentation files
if [ -f "$STAGING_DIR/README.md" ]; then
    cp "$STAGING_DIR/README.md" "$PKG_BUILD_DIR/usr/share/doc/$PACKAGE_NAME/"
fi

if [ -f "$STAGING_DIR/DEPENDENCIES.txt" ]; then
    cp "$STAGING_DIR/DEPENDENCIES.txt" "$PKG_BUILD_DIR/usr/share/doc/$PACKAGE_NAME/"
fi

# Create changelog
cat > "$PKG_BUILD_DIR/usr/share/doc/$PACKAGE_NAME/changelog" << EOF
wine-custom ($PACKAGE_VERSION) unstable; urgency=low

  * Custom Wine build for Business Central compatibility
  * Version: $WINE_VERSION
  * Git: $GIT_DESC
  * Built on $(date -u '+%Y-%m-%d %H:%M:%S UTC')

 -- Wine Custom Build <custom@example.com>  $(date -R)
EOF

gzip -9 "$PKG_BUILD_DIR/usr/share/doc/$PACKAGE_NAME/changelog"

# Create copyright file
cat > "$PKG_BUILD_DIR/usr/share/doc/$PACKAGE_NAME/copyright" << 'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: Wine
Source: https://www.winehq.org/

Files: *
Copyright: 1993-2024 Wine Developers
License: LGPL-2.1+
 This library is free software; you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public
 License as published by the Free Software Foundation; either
 version 2.1 of the License, or (at your option) any later version.
 .
 This library is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 Lesser General Public License for more details.
 .
 On Debian systems, the complete text of the GNU Lesser General
 Public License can be found in `/usr/share/common-licenses/LGPL-2.1'.

Files: debian/*
Copyright: 2025 Wine Custom Build
License: LGPL-2.1+
EOF

# Set proper permissions
print_info "Setting permissions..."
find "$PKG_BUILD_DIR/usr" -type d -exec chmod 755 {} \;
find "$PKG_BUILD_DIR/usr" -type f -exec chmod 644 {} \;
find "$PKG_BUILD_DIR/usr/local/bin" -type f -exec chmod 755 {} \;
find "$PKG_BUILD_DIR/usr/local/lib/wine" -name "*.so" -exec chmod 755 {} \;

# Build the package
print_info "Building .deb package..."
DEB_FILE="${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64.deb"

if ! dpkg-deb --build --root-owner-group "$PKG_BUILD_DIR" "$OUTPUT_DIR/$DEB_FILE"; then
    print_error "Failed to build .deb package"
    exit 1
fi

# Verify the package
print_info "Verifying package..."
if dpkg-deb --info "$OUTPUT_DIR/$DEB_FILE" > /dev/null 2>&1; then
    print_success "Package verified successfully"
else
    print_error "Package verification failed"
    exit 1
fi

# Print package information
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                .deb Package Built Successfully                ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
print_info "Package: $DEB_FILE"
print_info "Size: $(du -h "$OUTPUT_DIR/$DEB_FILE" | cut -f1)"
print_info "Location: $OUTPUT_DIR"
echo ""

# Show package info
dpkg-deb --info "$OUTPUT_DIR/$DEB_FILE"
echo ""

# Show package contents summary
print_info "Package contents summary:"
dpkg-deb --contents "$OUTPUT_DIR/$DEB_FILE" | head -20
echo "  ... ($(dpkg-deb --contents "$OUTPUT_DIR/$DEB_FILE" | wc -l) total files)"
echo ""

print_success "Installation command: sudo dpkg -i $DEB_FILE"
print_success "Or: sudo apt install ./$DEB_FILE"

# Cleanup
rm -rf "$PKG_BUILD_DIR"

exit 0
