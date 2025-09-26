#!/bin/bash
# Wine Build Script
# Quick rebuild script for development after code changes

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
WINE_SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$WINE_SOURCE_DIR/build"
WINE64_DIR="$BUILD_DIR/wine-64"
WINE32_DIR="$BUILD_DIR/wine-32"
JOBS=$(nproc)

# Function to print colored output
print_status() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} ✓ $1"
}

print_warning() {
    echo -e "${YELLOW}[$(date '+%H:%M:%S')]${NC} ⚠ $1"
}

print_error() {
    echo -e "${RED}[$(date '+%H:%M:%S')]${NC} ✗ $1"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -c, --clean     Run make clean before building"
    echo "  -f, --full      Full reconfigure and build (slower)"
    echo "  -q, --quick     Quick build only (no install)"
    echo "  -h, --help      Show this help message"
    echo ""
    echo "Default behavior: Incremental build and install"
}

# Parse command line arguments
CLEAN_BUILD=false
FULL_BUILD=false
QUICK_BUILD=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--clean)
            CLEAN_BUILD=true
            shift
            ;;
        -f|--full)
            FULL_BUILD=true
            shift
            ;;
        -q|--quick)
            QUICK_BUILD=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Ensure we're in the Wine source directory
if [[ ! -f "configure.ac" ]]; then
    print_error "This script must be run from the Wine source directory"
    exit 1
fi

print_status "Starting Wine build process..."
print_status "Source dir: $WINE_SOURCE_DIR"
print_status "Build jobs: $JOBS"

# Check if tools/make_unicode has been modified and regenerate locale data if needed
if [[ -f "tools/make_unicode" ]]; then
    # Check if make_unicode is newer than locale.nls or if locale.nls doesn't exist
    if [[ "tools/make_unicode" -nt "nls/locale.nls" ]] || [[ ! -f "nls/locale.nls" ]]; then
        print_warning "Detected changes to tools/make_unicode - regenerating locale data..."
        print_status "This may take a few minutes on first run (downloads Unicode data)..."
        
        # Run make_unicode to regenerate locale.nls
        if ./tools/make_unicode > /tmp/make_unicode.log 2>&1; then
            print_success "Locale data regenerated successfully"
            # Check if locale.nls was actually updated
            if [[ -f "nls/locale.nls" ]]; then
                print_status "nls/locale.nls has been updated"
            fi
        else
            print_error "Failed to regenerate locale data. Check /tmp/make_unicode.log for details"
            print_warning "Continuing build anyway, but locale fixes may not work properly"
        fi
    fi
fi

# Create build directories if they don't exist
mkdir -p "$WINE64_DIR" "$WINE32_DIR"

# Build 64-bit Wine
print_status "Building 64-bit Wine..."
cd "$WINE64_DIR"

if [[ "$FULL_BUILD" == true ]]; then
    print_status "Full reconfigure for 64-bit Wine..."
    ../../configure CC="ccache gcc" CROSSCC="ccache i686-w64-mingw32-gcc" --enable-win64
fi

if [[ "$CLEAN_BUILD" == true ]]; then
    print_status "Cleaning 64-bit build..."
    make clean
fi

print_status "Compiling 64-bit Wine (using $JOBS jobs)..."
make -j"$JOBS"
print_success "64-bit Wine compilation completed"

# Build 32-bit Wine
print_status "Building 32-bit Wine..."
cd "$WINE32_DIR"

if [[ "$FULL_BUILD" == true ]]; then
    print_status "Full reconfigure for 32-bit Wine..."
    ../../configure CC="ccache gcc" CROSSCC="ccache i686-w64-mingw32-gcc" --with-wine64=../wine-64
fi

if [[ "$CLEAN_BUILD" == true ]]; then
    print_status "Cleaning 32-bit build..."
    make clean
fi

print_status "Compiling 32-bit Wine (using $JOBS jobs)..."
make -j"$JOBS"
print_success "32-bit Wine compilation completed"

# Install Wine (unless quick build)
if [[ "$QUICK_BUILD" == false ]]; then
    print_status "Installing Wine..."
    
    cd "$WINE64_DIR"
    print_status "Installing 64-bit Wine..."
    sudo make install
    print_success "64-bit Wine installed"
    
    cd "$WINE32_DIR"
    print_status "Installing 32-bit Wine..."
    sudo make install
    print_success "32-bit Wine installed"
    
    print_success "Wine installation completed"
else
    print_warning "Skipping installation (quick build mode)"
fi

# Show Wine version
print_status "Checking Wine installation..."
WINE_VERSION=$(wine --version 2>/dev/null || echo "Wine not found in PATH")
print_success "Build completed! Wine version: $WINE_VERSION"

# Build summary
echo ""
echo "=================================="
echo "         BUILD SUMMARY            "
echo "=================================="
echo "Source directory: $WINE_SOURCE_DIR"
echo "64-bit build:     $WINE64_DIR"
echo "32-bit build:     $WINE32_DIR"
echo "Build jobs used:  $JOBS"
echo "Clean build:      $CLEAN_BUILD"
echo "Full rebuild:     $FULL_BUILD"
echo "Quick mode:       $QUICK_BUILD"
echo "Wine version:     $WINE_VERSION"
echo "=================================="

# Suggest next steps
echo ""
print_status "Next steps:"
echo "  • Test locale fix: cd /tmp && wine test_locale_enum.exe"
echo "  • Test BC Server: WINEPREFIX=~/.local/share/wineprefixes/bc1 wine <BC_Server_Path>"
echo "  • Debug issues:   WINEDEBUG=+locale,+httpapi wine <program>"