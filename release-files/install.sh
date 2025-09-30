#!/bin/bash
# Wine Custom Build Installer
# Installs Wine to specified prefix with validation

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default installation prefix
DEFAULT_PREFIX="/usr/local"
INSTALL_PREFIX=""

# Functions
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_usage() {
    cat << EOF
Wine Custom Build Installer

Usage: $0 [OPTIONS]

Options:
  --prefix PATH    Installation prefix (default: /usr/local)
  --check-only     Only check dependencies, don't install
  --help           Show this help message

Examples:
  # Install to default location (/usr/local)
  sudo $0

  # Install to custom location
  sudo $0 --prefix /opt/wine-custom

  # Check dependencies without installing
  $0 --check-only

Installation locations:
  /usr/local       - Standard, recommended (in system PATH)
  /opt/wine-custom - Alternative location (requires PATH setup)
  ~/.local         - User-local installation (no sudo needed)

EOF
}

check_root() {
    if [ "$EUID" -ne 0 ] && [ "$CHECK_ONLY" != "true" ]; then
        print_error "This script must be run as root for system-wide installation"
        echo "Use: sudo $0"
        echo "Or use --check-only to validate without installing"
        exit 1
    fi
}

check_architecture() {
    print_info "Checking system architecture..."

    ARCH=$(uname -m)
    if [ "$ARCH" != "x86_64" ]; then
        print_error "This Wine build requires x86_64 architecture"
        print_error "Your system: $ARCH"
        return 1
    fi

    print_success "Architecture: $ARCH ✓"
    return 0
}

check_multilib() {
    print_info "Checking 32-bit architecture support..."

    if ! dpkg --print-foreign-architectures 2>/dev/null | grep -q i386; then
        print_warning "32-bit architecture (i386) not enabled"
        echo "To enable, run:"
        echo "  sudo dpkg --add-architecture i386"
        echo "  sudo apt update"
        return 1
    fi

    print_success "32-bit support enabled ✓"
    return 0
}

check_dependencies() {
    print_info "Checking runtime dependencies..."

    local missing=0
    local required_packages=(
        "libc6:i386"
        "libx11-6:i386"
        "libfreetype6:i386"
        "libfontconfig1:i386"
    )

    for package in "${required_packages[@]}"; do
        if ! dpkg -l "$package" 2>/dev/null | grep -q "^ii"; then
            print_warning "Missing: $package"
            ((missing++))
        fi
    done

    if [ $missing -gt 0 ]; then
        print_warning "$missing required packages are missing"
        echo ""
        echo "Install dependencies with:"
        echo "  sudo apt install -y libc6:i386 libx11-6:i386 libx11-6 \\"
        echo "    libfreetype6:i386 libfreetype6 libfontconfig1:i386 libfontconfig1 \\"
        echo "    libxcursor1:i386 libxcursor1 libxi6:i386 libxi6 \\"
        echo "    libxext6:i386 libxext6 libxrandr2:i386 libxrandr2 \\"
        echo "    libxrender1:i386 libxrender1 libxinerama1:i386 libxinerama1 \\"
        echo "    libgl1:i386 libgl1 libasound2:i386 libasound2 \\"
        echo "    libdbus-1-3:i386 libdbus-1-3 libgnutls30:i386 libgnutls30"
        return 1
    fi

    print_success "All required dependencies installed ✓"
    return 0
}

check_disk_space() {
    print_info "Checking available disk space..."

    local prefix_dir=$(dirname "$INSTALL_PREFIX")
    local available=$(df -BG "$prefix_dir" | tail -1 | awk '{print $4}' | sed 's/G//')
    local required=2

    if [ "$available" -lt "$required" ]; then
        print_warning "Low disk space: ${available}GB available, ${required}GB required"
        return 1
    fi

    print_success "Disk space: ${available}GB available ✓"
    return 0
}

verify_extraction() {
    print_info "Verifying installation files..."

    # Check if we're in the extracted tarball directory
    if [ ! -d "usr/local/bin" ] || [ ! -d "usr/local/lib/wine" ]; then
        print_error "Installation files not found in current directory"
        print_error "Please run this script from the extracted tarball directory"
        return 1
    fi

    # Verify critical files exist
    if [ ! -f "usr/local/bin/wine" ]; then
        print_error "Wine binary not found"
        return 1
    fi

    if [ ! -f "usr/local/lib/wine/x86_64-windows/kernel32.dll" ]; then
        print_error "Critical DLLs missing"
        return 1
    fi

    print_success "Installation files verified ✓"
    return 0
}

perform_installation() {
    print_info "Installing Wine to $INSTALL_PREFIX..."

    # Determine if we need to transform paths
    if [ "$INSTALL_PREFIX" = "/usr/local" ]; then
        # Direct extraction
        tar -C / -xzf ../$(basename $(pwd)).tar.gz 2>/dev/null || {
            # If tarball not found, we're already extracted
            cp -r usr/local/* "$INSTALL_PREFIX/"
        }
    else
        # Transform paths for custom prefix
        mkdir -p "$INSTALL_PREFIX"
        cp -r usr/local/* "$INSTALL_PREFIX/"
    fi

    print_success "Files copied to $INSTALL_PREFIX"

    # Create uninstall script
    create_uninstall_script
}

create_uninstall_script() {
    local uninstall_script="$INSTALL_PREFIX/bin/wine-uninstall.sh"

    cat > "$uninstall_script" << 'UNINSTALL_EOF'
#!/bin/bash
# Wine Custom Build Uninstaller

set -e

INSTALL_PREFIX="PREFIX_PLACEHOLDER"

echo "This will remove Wine from: $INSTALL_PREFIX"
read -p "Are you sure? (yes/no) " -r
if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    echo "Uninstall cancelled"
    exit 0
fi

echo "Removing Wine files..."
rm -f "$INSTALL_PREFIX/bin/wine"*
rm -rf "$INSTALL_PREFIX/lib/wine"
rm -rf "$INSTALL_PREFIX/share/wine"

echo "Wine uninstalled successfully"
echo "Note: Wine prefixes in ~/.wine are preserved"
echo "To remove: rm -rf ~/.wine"
UNINSTALL_EOF

    sed -i "s|PREFIX_PLACEHOLDER|$INSTALL_PREFIX|g" "$uninstall_script"
    chmod +x "$uninstall_script"

    print_info "Uninstaller created: $uninstall_script"
}

print_post_install() {
    echo ""
    echo "======================================"
    echo "  Wine Custom Build Installed! ✓"
    echo "======================================"
    echo ""
    echo "Installation location: $INSTALL_PREFIX"
    echo ""

    if [ "$INSTALL_PREFIX" != "/usr/local" ]; then
        print_warning "Wine installed to non-standard location"
        echo "Add to your PATH:"
        echo "  export PATH=\"$INSTALL_PREFIX/bin:\$PATH\""
        echo ""
        echo "Make permanent (add to ~/.bashrc):"
        echo "  echo 'export PATH=\"$INSTALL_PREFIX/bin:\$PATH\"' >> ~/.bashrc"
        echo ""
    fi

    echo "Test installation:"
    echo "  wine --version"
    echo "  wine cmd /c echo \"Hello from Wine\""
    echo ""
    echo "Configuration:"
    echo "  winecfg          # Configure Wine settings"
    echo "  wineboot         # Initialize Wine prefix"
    echo ""
    echo "Uninstall:"
    echo "  $INSTALL_PREFIX/bin/wine-uninstall.sh"
    echo ""
    echo "Documentation:"
    echo "  See README.md in this directory"
    echo ""
}

# Parse arguments
CHECK_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --prefix)
            INSTALL_PREFIX="$2"
            shift 2
            ;;
        --check-only)
            CHECK_ONLY=true
            shift
            ;;
        --help)
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

# Set default prefix if not specified
if [ -z "$INSTALL_PREFIX" ]; then
    INSTALL_PREFIX="$DEFAULT_PREFIX"
fi

# Main execution
echo ""
echo "======================================"
echo "  Wine Custom Build Installer"
echo "======================================"
echo ""

# Run checks
CHECKS_PASSED=true

check_architecture || CHECKS_PASSED=false
check_multilib || CHECKS_PASSED=false
check_dependencies || CHECKS_PASSED=false

if [ "$CHECK_ONLY" = "true" ]; then
    echo ""
    if [ "$CHECKS_PASSED" = "true" ]; then
        print_success "All checks passed! System is ready for Wine installation"
        exit 0
    else
        print_error "Some checks failed. Please fix the issues above."
        exit 1
    fi
fi

# Verify we're in the right directory
verify_extraction || exit 1

# Check root
check_root

# Check disk space
check_disk_space || {
    read -p "Continue anyway? (yes/no) " -r
    [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]] && exit 1
}

# Perform installation
if [ "$CHECKS_PASSED" = "false" ]; then
    print_warning "Some dependency checks failed"
    read -p "Continue installation anyway? (yes/no) " -r
    [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]] && exit 1
fi

perform_installation
print_post_install

exit 0
