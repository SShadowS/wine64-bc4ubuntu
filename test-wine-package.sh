#!/bin/bash
# Wine Package Test Suite
# Comprehensive testing for Wine custom build packages

# Don't exit on pipe errors (tar | head can cause broken pipe)
set -e
set -o pipefail || true
# Ignore SIGPIPE to prevent broken pipe errors from killing the script
trap '' PIPE 2>/dev/null || true

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
PASSED=0
FAILED=0
SKIPPED=0
TOTAL_TESTS=0

# Test results array
declare -a FAILED_TESTS

# Configuration
WINE_PREFIX="${WINE_PREFIX:-/usr/local}"
VERBOSE="${VERBOSE:-false}"

# Functions
print_header() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

test_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((PASSED++))
    ((TOTAL_TESTS++))
}

test_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    FAILED_TESTS+=("$1: $2")
    ((FAILED++))
    ((TOTAL_TESTS++))
}

test_skip() {
    echo -e "${YELLOW}⊘ SKIP${NC}: $1"
    ((SKIPPED++))
    ((TOTAL_TESTS++))
}

verbose() {
    if [ "$VERBOSE" = "true" ]; then
        echo -e "${BLUE}  [DEBUG]${NC} $1"
    fi
}

# Test Level 1: Package Integrity
test_package_structure() {
    print_header "Level 1: Package Structure Tests"

    # Test 1.1: Check tarball exists
    if [ -n "$TARBALL" ] && [ -f "$TARBALL" ]; then
        test_pass "Tarball exists: $TARBALL"
    else
        test_fail "Tarball not found" "TARBALL variable not set or file missing"
        return 1
    fi

    # Test 1.2: Tarball is readable
    # Test tarball validity without pipes to avoid broken pipe errors
    TAR_TEST_RESULT=0
    tar -tzf "$TARBALL" > /tmp/tar_test.log 2>&1 || TAR_TEST_RESULT=$?

    if [ "$TAR_TEST_RESULT" -eq 0 ]; then
        test_pass "Tarball is valid and readable"
    else
        echo "Tar test failed with exit code: $TAR_TEST_RESULT"
        echo "Error output:"
        cat /tmp/tar_test.log 2>/dev/null || echo "(no error log)"
        test_fail "Tarball corrupt or unreadable" "tar -tzf failed with code $TAR_TEST_RESULT"
        return 1
    fi

    # Test 1.3: Check main directories
    for dir in "usr/local/bin" "usr/local/lib/wine" "usr/local/share/wine"; do
        if tar -tzf "$TARBALL" | grep -q "^${dir}/"; then
            test_pass "Directory present: $dir"
        else
            test_fail "Directory missing: $dir" "Required directory not in tarball"
        fi
    done

    # Test 1.4: Check documentation files
    for file in "README.md" "DEPENDENCIES.txt" "install.sh"; do
        if tar -tzf "$TARBALL" | grep -q "^${file}$"; then
            test_pass "Documentation present: $file"
        else
            test_fail "Documentation missing: $file" "User doc not included"
        fi
    done

    # Test 1.5: Check tarball size
    SIZE_MB=$(du -m "$TARBALL" | cut -f1)
    if [ "$SIZE_MB" -gt 100 ] && [ "$SIZE_MB" -lt 1000 ]; then
        test_pass "Tarball size reasonable: ${SIZE_MB}MB"
        verbose "Expected range: 100-1000 MB"
    else
        test_fail "Tarball size suspicious: ${SIZE_MB}MB" "Expected 100-1000 MB"
    fi
}

# Test Level 2: Installation Tests
test_installation() {
    print_header "Level 2: Installation Tests"

    # Test 2.1: Wine binary exists
    if [ -f "$WINE_PREFIX/bin/wine" ]; then
        test_pass "Wine binary installed"
    else
        test_fail "Wine binary missing" "Expected: $WINE_PREFIX/bin/wine"
        return 1
    fi

    # Test 2.2: Wine binary is executable
    if [ -x "$WINE_PREFIX/bin/wine" ]; then
        test_pass "Wine binary is executable"
    else
        test_fail "Wine binary not executable" "chmod +x may be needed"
    fi

    # Test 2.3: Check binary type
    FILE_TYPE=$(file "$WINE_PREFIX/bin/wine" | grep -o "ELF.*")
    if echo "$FILE_TYPE" | grep -q "64-bit"; then
        test_pass "Wine binary is 64-bit: $FILE_TYPE"
    else
        test_fail "Wine binary wrong type" "Expected ELF 64-bit, got: $FILE_TYPE"
    fi

    # Test 2.4: Wineserver exists
    if [ -f "$WINE_PREFIX/bin/wineserver" ]; then
        test_pass "Wineserver binary installed"
    else
        test_fail "Wineserver missing" "Critical component not installed"
    fi

    # Test 2.5: Wine libraries directory
    if [ -d "$WINE_PREFIX/lib/wine" ]; then
        test_pass "Wine library directory exists"
    else
        test_fail "Wine library directory missing" "Expected: $WINE_PREFIX/lib/wine"
        return 1
    fi

    # Test 2.6: Check all four architecture directories
    for arch_dir in "i386-unix" "i386-windows" "x86_64-unix" "x86_64-windows"; do
        if [ -d "$WINE_PREFIX/lib/wine/$arch_dir" ]; then
            test_pass "Architecture directory: $arch_dir"
        else
            test_fail "Missing architecture: $arch_dir" "Incomplete Wine build"
        fi
    done
}

# Test Level 3: DLL and Library Tests
test_dlls() {
    print_header "Level 3: DLL and Library Tests"

    # Test 3.1: Critical DLLs - 64-bit
    for dll in "kernel32.dll" "ntdll.dll" "user32.dll" "advapi32.dll"; do
        if [ -f "$WINE_PREFIX/lib/wine/x86_64-windows/$dll" ]; then
            test_pass "64-bit DLL present: $dll"
        else
            test_fail "64-bit DLL missing: $dll" "Critical Windows API missing"
        fi
    done

    # Test 3.2: Critical DLLs - 32-bit
    for dll in "kernel32.dll" "ntdll.dll" "user32.dll"; do
        if [ -f "$WINE_PREFIX/lib/wine/i386-windows/$dll" ]; then
            test_pass "32-bit DLL present: $dll"
        else
            test_fail "32-bit DLL missing: $dll" "Critical Windows API missing"
        fi
    done

    # Test 3.3: Unix libraries - 64-bit
    if [ -f "$WINE_PREFIX/lib/wine/x86_64-unix/ntdll.so" ]; then
        test_pass "64-bit Unix library: ntdll.so"
    else
        test_fail "64-bit Unix library missing" "ntdll.so not found"
    fi

    # Test 3.4: Unix libraries - 32-bit
    if [ -f "$WINE_PREFIX/lib/wine/i386-unix/ntdll.so" ]; then
        test_pass "32-bit Unix library: ntdll.so"
    else
        test_fail "32-bit Unix library missing" "ntdll.so not found"
    fi

    # Test 3.5: DLL count - 64-bit
    DLL_COUNT_64=$(find "$WINE_PREFIX/lib/wine/x86_64-windows" -name "*.dll" 2>/dev/null | wc -l)
    if [ "$DLL_COUNT_64" -gt 300 ]; then
        test_pass "64-bit DLL count: $DLL_COUNT_64 (good)"
    else
        test_fail "Too few 64-bit DLLs: $DLL_COUNT_64" "Expected >300"
    fi

    # Test 3.6: DLL count - 32-bit
    DLL_COUNT_32=$(find "$WINE_PREFIX/lib/wine/i386-windows" -name "*.dll" 2>/dev/null | wc -l)
    if [ "$DLL_COUNT_32" -gt 300 ]; then
        test_pass "32-bit DLL count: $DLL_COUNT_32 (good)"
    else
        test_fail "Too few 32-bit DLLs: $DLL_COUNT_32" "Expected >300"
    fi

    # Test 3.7: Total DLL count
    TOTAL_DLLS=$(find "$WINE_PREFIX/lib/wine" -name "*.dll" 2>/dev/null | wc -l)
    verbose "Total DLLs found: $TOTAL_DLLS"
    if [ "$TOTAL_DLLS" -gt 600 ]; then
        test_pass "Total DLL count: $TOTAL_DLLS"
    else
        test_fail "Total DLL count low: $TOTAL_DLLS" "Expected >600"
    fi
}

# Test Level 4: Data Files
test_data_files() {
    print_header "Level 4: Data Files Tests"

    # Test 4.1: Locale data file
    LOCALE_FILE="$WINE_PREFIX/share/wine/nls/locale.nls"
    if [ -f "$LOCALE_FILE" ]; then
        test_pass "Locale data file exists"
    else
        test_fail "Locale data file missing" "Custom locale fixes not included"
        return 1
    fi

    # Test 4.2: Locale data size
    LOCALE_SIZE=$(stat -c%s "$LOCALE_FILE" 2>/dev/null || stat -f%z "$LOCALE_FILE" 2>/dev/null)
    if [ "$LOCALE_SIZE" -gt 100000 ]; then
        SIZE_KB=$((LOCALE_SIZE / 1024))
        test_pass "Locale data size: ${SIZE_KB}KB (good)"
    else
        test_fail "Locale data too small: $LOCALE_SIZE bytes" "Expected >100KB"
    fi

    # Test 4.3: Wine INF file
    if [ -f "$WINE_PREFIX/share/wine/wine.inf" ]; then
        test_pass "Wine INF file present"
    else
        test_fail "Wine INF missing" "Configuration file not installed"
    fi

    # Test 4.4: Fonts directory
    if [ -d "$WINE_PREFIX/share/wine/fonts" ]; then
        FONT_COUNT=$(find "$WINE_PREFIX/share/wine/fonts" -type f 2>/dev/null | wc -l)
        if [ "$FONT_COUNT" -gt 0 ]; then
            test_pass "Wine fonts present: $FONT_COUNT fonts"
        else
            test_skip "No fonts found (may be optional)"
        fi
    else
        test_skip "Fonts directory missing (may be optional)"
    fi

    # Test 4.5: Version file
    if [ -f "$WINE_PREFIX/share/wine/wine-version.txt" ]; then
        VERSION=$(cat "$WINE_PREFIX/share/wine/wine-version.txt")
        test_pass "Version file present: $VERSION"
    else
        test_skip "Version file not found (optional)"
    fi
}

# Test Level 5: Runtime Tests
test_runtime() {
    print_header "Level 5: Runtime Tests"

    # Test 5.1: Wine version check
    if WINE_VER=$("$WINE_PREFIX/bin/wine" --version 2>/dev/null); then
        test_pass "Wine starts: $WINE_VER"
    else
        test_fail "Wine won't start" "wine --version failed"
        return 1
    fi

    # Test 5.2: Wine64 available
    if [ -f "$WINE_PREFIX/bin/wine64" ] || [ -L "$WINE_PREFIX/bin/wine64" ]; then
        if "$WINE_PREFIX/bin/wine64" --version > /dev/null 2>&1; then
            test_pass "Wine64 works"
        else
            test_fail "Wine64 exists but won't run" "Check dependencies"
        fi
    else
        test_fail "Wine64 not available" "64-bit support missing"
    fi

    # Test 5.3: Simple command execution
    if "$WINE_PREFIX/bin/wine" cmd /c exit 2>/dev/null; then
        test_pass "Wine executes commands"
    else
        test_fail "Wine command execution failed" "cmd /c exit failed"
    fi

    # Test 5.4: Echo test
    OUTPUT=$("$WINE_PREFIX/bin/wine" cmd /c echo test 2>/dev/null || echo "")
    if echo "$OUTPUT" | grep -q "test"; then
        test_pass "Wine command output works"
    else
        test_fail "Wine command output broken" "Expected 'test', got: $OUTPUT"
    fi

    # Test 5.5: Check wineserver
    if "$WINE_PREFIX/bin/wineserver" --version > /dev/null 2>&1; then
        test_pass "Wineserver functional"
    else
        test_fail "Wineserver not working" "Core component failed"
    fi

    # Clean up wine processes
    "$WINE_PREFIX/bin/wineserver" -k 2>/dev/null || true
}

# Test Level 6: Dependency Tests
test_dependencies() {
    print_header "Level 6: Dependency Tests"

    # Test 6.1: Check ldd on wine binary
    if ldd "$WINE_PREFIX/bin/wine" > /dev/null 2>&1; then
        test_pass "Wine binary has resolvable dependencies"

        # Check for missing libraries
        MISSING=$(ldd "$WINE_PREFIX/bin/wine" 2>&1 | grep "not found" || true)
        if [ -z "$MISSING" ]; then
            test_pass "No missing libraries"
        else
            test_fail "Missing libraries detected" "$MISSING"
        fi
    else
        test_fail "ldd check failed" "Cannot analyze dependencies"
    fi

    # Test 6.2: Check multilib support
    if dpkg --print-foreign-architectures 2>/dev/null | grep -q i386; then
        test_pass "i386 architecture enabled"
    else
        test_fail "i386 architecture not enabled" "Run: dpkg --add-architecture i386"
    fi

    # Test 6.3: Check critical runtime packages
    CRITICAL_PKGS=("libc6:i386" "libx11-6:i386" "libfreetype6:i386")
    MISSING_PKGS=0
    for pkg in "${CRITICAL_PKGS[@]}"; do
        if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            verbose "Package installed: $pkg"
        else
            test_fail "Missing runtime package: $pkg" "Install with apt"
            ((MISSING_PKGS++))
        fi
    done
    if [ "$MISSING_PKGS" -eq 0 ]; then
        test_pass "Critical runtime packages installed"
    fi
}

# Usage
show_usage() {
    cat << EOF
Wine Package Test Suite

Usage: $0 [OPTIONS]

Options:
    --tarball PATH      Test package from tarball
    --installed         Test installed Wine (default: /usr/local)
    --prefix PATH       Specify Wine installation prefix
    --verbose           Enable verbose output
    --help              Show this help

Examples:
    # Test a tarball before installation
    $0 --tarball output/wine-custom-10.15.tar.gz

    # Test installed Wine
    $0 --installed

    # Test custom installation
    $0 --prefix /opt/wine-custom --installed

    # Verbose mode
    $0 --tarball wine.tar.gz --verbose

EOF
}

# Main execution
main() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║           Wine Custom Build - Test Suite                     ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""

    # Run test suites
    if [ -n "$TARBALL" ]; then
        test_package_structure
    fi

    if [ "$TEST_INSTALLED" = "true" ]; then
        test_installation
        test_dlls
        test_data_files
        test_runtime
        test_dependencies
    fi

    # Print summary
    print_header "Test Summary"

    echo -e "${GREEN}Passed:  $PASSED${NC}"
    echo -e "${RED}Failed:  $FAILED${NC}"
    echo -e "${YELLOW}Skipped: $SKIPPED${NC}"
    echo -e "Total:   $TOTAL_TESTS"
    echo ""

    # Show failed tests
    if [ "$FAILED" -gt 0 ]; then
        echo -e "${RED}Failed Tests:${NC}"
        for test in "${FAILED_TESTS[@]}"; do
            echo -e "  ${RED}✗${NC} $test"
        done
        echo ""
    fi

    # Final result
    if [ "$FAILED" -eq 0 ]; then
        echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                 ALL TESTS PASSED! ✓                          ║${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
        exit 0
    else
        echo -e "${RED}╔═══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║                 SOME TESTS FAILED!                            ║${NC}"
        echo -e "${RED}╚═══════════════════════════════════════════════════════════════╝${NC}"
        exit 1
    fi
}

# Parse arguments
TARBALL=""
TEST_INSTALLED=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --tarball)
            TARBALL="$2"
            shift 2
            ;;
        --installed)
            TEST_INSTALLED=true
            shift
            ;;
        --prefix)
            WINE_PREFIX="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Validation
if [ -z "$TARBALL" ] && [ "$TEST_INSTALLED" != "true" ]; then
    echo "Error: Must specify --tarball or --installed"
    show_usage
    exit 1
fi

# Run main
main
