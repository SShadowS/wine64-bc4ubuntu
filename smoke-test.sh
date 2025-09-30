#!/bin/bash
# Wine Smoke Test
# Quick functional test to verify Wine works

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

WINE_BIN="${WINE_BIN:-wine}"
TEST_DIR=$(mktemp -d)
TESTS_PASSED=0
TESTS_FAILED=0

cleanup() {
    rm -rf "$TEST_DIR"
    wineserver -k 2>/dev/null || true
}

trap cleanup EXIT

print_test() {
    echo -e "\n${YELLOW}>>> Test: $1${NC}"
}

test_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((TESTS_PASSED++))
}

test_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    ((TESTS_FAILED++))
}

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║              Wine Smoke Test Suite                            ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "Wine binary: $WINE_BIN"
echo "Test directory: $TEST_DIR"
echo ""

# Test 1: Version check
print_test "Wine version check"
if WINE_VERSION=$($WINE_BIN --version 2>&1); then
    test_pass "Wine version: $WINE_VERSION"
else
    test_fail "Wine version check failed"
    exit 1
fi

# Test 2: Simple exit
print_test "Simple command (exit)"
if $WINE_BIN cmd /c exit 2>/dev/null; then
    test_pass "Wine executes commands"
else
    test_fail "Wine cannot execute commands"
fi

# Test 3: Echo test
print_test "Command output (echo)"
OUTPUT=$($WINE_BIN cmd /c "echo SmokeTest" 2>/dev/null || echo "")
if echo "$OUTPUT" | grep -q "SmokeTest"; then
    test_pass "Wine command output works"
else
    test_fail "Wine command output broken (got: $OUTPUT)"
fi

# Test 4: Environment variables
print_test "Environment variables"
OUTPUT=$($WINE_BIN cmd /c "set TEST_VAR=TestValue && echo %TEST_VAR%" 2>/dev/null || echo "")
if echo "$OUTPUT" | grep -q "TestValue"; then
    test_pass "Environment variables work"
else
    test_fail "Environment variables broken"
fi

# Test 5: File operations
print_test "File operations"
TEST_FILE="$TEST_DIR/test.txt"
if $WINE_BIN cmd /c "echo TestContent > Z:\\$(basename $TEST_DIR)\\test.txt" 2>/dev/null; then
    if [ -f "$TEST_FILE" ]; then
        test_pass "File creation works"
    else
        test_fail "File not created"
    fi
else
    test_fail "File operation failed"
fi

# Test 6: Directory listing
print_test "Directory listing"
if $WINE_BIN cmd /c "dir C:\\" > /dev/null 2>&1; then
    test_pass "Directory listing works"
else
    test_fail "Directory listing failed"
fi

# Test 7: Windows version
print_test "Windows version info"
if OUTPUT=$($WINE_BIN cmd /c ver 2>/dev/null); then
    test_pass "Version command: $OUTPUT"
else
    test_fail "Version command failed"
fi

# Test 8: 64-bit support (if wine64 exists)
print_test "64-bit support"
if command -v wine64 >/dev/null 2>&1 || [ -f "$(dirname $WINE_BIN)/wine64" ]; then
    WINE64="${WINE64:-$(dirname $WINE_BIN)/wine64}"
    if $WINE64 cmd /c exit 2>/dev/null; then
        test_pass "Wine64 works"
    else
        test_fail "Wine64 exists but doesn't work"
    fi
else
    echo "  (Wine64 not available, skipping)"
fi

# Test 9: Registry access
print_test "Registry access"
if $WINE_BIN reg query "HKLM\\System" > /dev/null 2>&1; then
    test_pass "Registry queries work"
else
    test_fail "Registry access failed"
fi

# Test 10: Wineserver
print_test "Wineserver"
WINESERVER="${WINESERVER:-$(dirname $WINE_BIN)/wineserver}"
if [ -x "$WINESERVER" ]; then
    if $WINESERVER --version > /dev/null 2>&1; then
        test_pass "Wineserver functional"
    else
        test_fail "Wineserver not working"
    fi
else
    test_fail "Wineserver not found or not executable"
fi

# Summary
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    Test Summary                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All smoke tests passed!${NC}"
    echo ""
    echo "Wine is functional and ready to use."
    exit 0
else
    echo -e "${RED}✗ Some smoke tests failed!${NC}"
    echo ""
    echo "Wine may have issues. Check the failures above."
    exit 1
fi
