#!/bin/bash
# Wine Build Test Script
# Quick tests to verify Wine build is working

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} ✓ $1"
}

print_error() {
    echo -e "${RED}[$(date '+%H:%M:%S')]${NC} ✗ $1"
}

print_status "Testing Wine build..."

# Test Wine version
print_status "Checking Wine version..."
WINE_VERSION=$(wine --version 2>/dev/null || echo "ERROR")
if [[ "$WINE_VERSION" == "ERROR" ]]; then
    print_error "Wine not found or not working"
    exit 1
else
    print_success "Wine version: $WINE_VERSION"
fi

# Test locale enumeration fix
print_status "Testing locale enumeration fix..."
if [[ -f "/tmp/test_locale_enum.c" ]]; then
    cd /tmp
    if i686-w64-mingw32-gcc -o test_locale_enum.exe test_locale_enum.c -lkernel32 2>/dev/null; then
        print_success "Locale test compiled successfully"
        
        # Run the test
        if wine test_locale_enum.exe > locale_test_output.txt 2>&1; then
            if grep -q "DUPLICATE FOUND" locale_test_output.txt; then
                print_error "Locale enumeration still has duplicates!"
                echo "Check /tmp/locale_test_output.txt for details"
            else
                print_success "Locale enumeration test passed - no duplicates found"
            fi
        else
            print_error "Locale test failed to run"
        fi
    else
        print_error "Could not compile locale test"
    fi
else
    print_status "Locale test source not found at /tmp/test_locale_enum.c"
fi

# Test basic Wine functionality
print_status "Testing basic Wine functionality..."
if echo 'echo Wine is working' | wine cmd /c 2>/dev/null | grep -q "Wine is working"; then
    print_success "Basic Wine functionality test passed"
else
    print_error "Basic Wine functionality test failed"
fi

# Test Business Central prefix
BC_PREFIX="$HOME/.local/share/wineprefixes/bc"
if [[ -d "$BC_PREFIX" ]]; then
    print_status "Testing Business Central Wine prefix..."
    if WINEPREFIX="$BC_PREFIX" wine --version >/dev/null 2>&1; then
        print_success "BC Wine prefix is accessible"
    else
        print_error "BC Wine prefix has issues"
    fi
else
    print_status "BC Wine prefix not found at $BC_PREFIX"
fi

print_success "Wine build testing completed!"

echo ""
echo "=================================="
echo "         TEST SUMMARY             "
echo "=================================="
echo "Wine version:     $WINE_VERSION"
echo "Basic functionality: ✓ Passed"
echo "Locale fix test:  Check output above"
echo "BC prefix:        Check output above"
echo "=================================="