#!/bin/bash
set -e

STAGING_DIR="/staging"
OUTPUT_DIR="/output"
JOBS=$(nproc)

echo "=== Wine Release Build (Container) ==="
echo "Jobs: $JOBS"
echo

# Regenerate locale data
echo ">>> Regenerating locale data..."
cd /wine-src/tools
perl make_unicode
cd /wine-src

# Create build directories
mkdir -p build/wine-64 build/wine-32

# Build 64-bit Wine
echo ">>> Building 64-bit Wine..."
cd build/wine-64
../../configure \
    CC="ccache gcc" \
    CROSSCC="ccache x86_64-w64-mingw32-gcc" \
    --enable-win64 \
    --prefix=/usr/local \
    --disable-tests
make -j"$JOBS" || {
    echo "ERROR: 64-bit Wine build failed!"
    exit 1
}
cd ../..

# Build 32-bit Wine
echo ">>> Building 32-bit Wine..."
cd build/wine-32
../../configure \
    CC="ccache gcc -m32" \
    CROSSCC="ccache i686-w64-mingw32-gcc" \
    PKG_CONFIG_PATH=/usr/lib/i386-linux-gnu/pkgconfig \
    --with-wine64=../wine-64 \
    --prefix=/usr/local \
    --disable-tests
make -j"$JOBS" || {
    echo "ERROR: 32-bit Wine build failed!"
    exit 1
}
cd ../..

# Install to staging
echo ">>> Installing to staging..."
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR"
make -C build/wine-64 install DESTDIR="$STAGING_DIR"
make -C build/wine-32 install DESTDIR="$STAGING_DIR"

# Generate version info
echo ">>> Generating version info..."
"$STAGING_DIR/usr/local/bin/wine" --version > \
    "$STAGING_DIR/usr/local/share/wine/wine-version.txt"

# Copy user documentation to staging
echo ">>> Adding user documentation..."
cp /wine-src/release-files/README.md "$STAGING_DIR/"
cp /wine-src/release-files/DEPENDENCIES.txt "$STAGING_DIR/"
cp /wine-src/release-files/install.sh "$STAGING_DIR/"
chmod +x "$STAGING_DIR/install.sh"

# Validate staging directory has content
echo ">>> Validating staging directory..."
if [ ! -d "$STAGING_DIR/usr" ]; then
    echo "ERROR: usr/ directory not found in staging!"
    echo "Build likely failed. Contents of staging:"
    ls -la "$STAGING_DIR" || echo "Staging dir empty"
    exit 1
fi

if [ ! -f "$STAGING_DIR/usr/local/bin/wine" ]; then
    echo "ERROR: wine binary not found!"
    echo "Installation failed. Check build logs above."
    exit 1
fi

# Create tarball
echo ">>> Creating release tarball..."
cd "$STAGING_DIR"
WINE_VER=$(cat usr/local/share/wine/wine-version.txt | sed 's/wine-//')
GIT_DESC=$(cd /wine-src && git describe --always --dirty 2>/dev/null || echo "unknown")
VERSION="${WINE_VER}-${GIT_DESC}"
TARBALL="wine-custom-${VERSION}.tar.gz"

# Package everything
echo "Creating tarball with: usr/ README.md DEPENDENCIES.txt install.sh"
tar -czf "/output/$TARBALL" usr/ README.md DEPENDENCIES.txt install.sh || {
    echo "ERROR: Failed to create tarball!"
    echo "Contents of staging directory:"
    ls -la
    exit 1
}

# Validate the package
echo ">>> Validating package..."

# Check tarball was created
if [ ! -f "/output/$TARBALL" ]; then
    echo "ERROR: Tarball not created!"
    exit 1
fi

# Check tarball is readable
if ! tar -tzf "/output/$TARBALL" > /dev/null 2>&1; then
    echo "ERROR: Tarball is corrupt!"
    exit 1
fi

# Verify critical files in tarball
echo "Checking package contents..."
MISSING=0

for path in "usr/local/bin/wine" \
            "usr/local/lib/wine/x86_64-windows/kernel32.dll" \
            "usr/local/lib/wine/i386-windows/kernel32.dll" \
            "usr/local/share/wine/nls/locale.nls" \
            "README.md" \
            "install.sh"; do
    if ! tar -tzf "/output/$TARBALL" | grep -q "^${path}$"; then
        echo "  WARNING: Missing $path"
        ((MISSING++))
    fi
done

if [ $MISSING -gt 0 ]; then
    echo "WARNING: $MISSING critical files missing from package"
else
    echo "✓ All critical files present"
fi

# Count DLLs in package
DLL_COUNT=$(tar -tzf "/output/$TARBALL" | grep "\.dll$" | wc -l)
echo "✓ DLL count: $DLL_COUNT"

if [ $DLL_COUNT -lt 600 ]; then
    echo "WARNING: DLL count seems low (expected >600)"
fi

# Build .deb package
echo ">>> Building .deb package..."
if [ -f "/wine-src/build-deb.sh" ]; then
    /wine-src/build-deb.sh
    DEB_PACKAGE=$(ls /output/*.deb 2>/dev/null | head -1)
    if [ -f "$DEB_PACKAGE" ]; then
        echo "✓ .deb package created: $(basename $DEB_PACKAGE)"
    else
        echo "WARNING: .deb package build failed"
    fi
else
    echo "WARNING: build-deb.sh not found, skipping .deb package"
fi

echo
echo "=== Build Complete ==="
echo "Version: $VERSION"
echo ""
echo "Tarball:"
echo "  $TARBALL"
echo "  Size: $(du -h "/output/$TARBALL" | cut -f1)"
if [ -f "$DEB_PACKAGE" ]; then
    echo ""
    echo ".deb Package:"
    echo "  $(basename $DEB_PACKAGE)"
    echo "  Size: $(du -h "$DEB_PACKAGE" | cut -f1)"
fi
echo ""
ls -lh "/output/"

# Fix permissions on output files for the host user
echo ""
echo ">>> Fixing file permissions..."
if [ -n "$HOST_UID" ] && [ -n "$HOST_GID" ]; then
    chown -R $HOST_UID:$HOST_GID /output 2>/dev/null || true
    chown -R $HOST_UID:$HOST_GID /wine-src/build 2>/dev/null || true
    echo "Permissions fixed for host user $HOST_UID:$HOST_GID"
fi

exit 0
