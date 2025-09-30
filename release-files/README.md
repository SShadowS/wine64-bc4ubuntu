# Wine Custom Build

This is a custom build of Wine with enhancements for Business Central / BC compatibility.

## Version

Check the installed version:
```bash
wine --version
```

## Installation

### Quick Install (System-Wide)

```bash
# Extract tarball to system
sudo tar -C / -xzf wine-custom-*.tar.gz

# Verify installation
wine --version
```

Wine will be installed to `/usr/local/` and available system-wide.

### Using the Installer

For guided installation with dependency checking:

```bash
# Extract tarball first
tar -xzf wine-custom-*.tar.gz
cd wine-custom-*/

# Run installer
sudo ./install.sh

# Or install to custom location
sudo ./install.sh --prefix /opt/wine-custom

# Check dependencies without installing
./install.sh --check-only
```

### Custom Location Installation

```bash
# Extract to custom prefix
sudo tar -C / --transform='s,usr/local,opt/wine-custom,' \
    -xzf wine-custom-*.tar.gz

# Add to PATH
export PATH="/opt/wine-custom/bin:$PATH"

# Make permanent (add to ~/.bashrc)
echo 'export PATH="/opt/wine-custom/bin:$PATH"' >> ~/.bashrc
```

## System Requirements

### Operating System
- Ubuntu 22.04 LTS or newer
- Debian 11 (Bullseye) or newer
- Other Debian-based distributions
- x86_64 (64-bit) architecture

### Disk Space
- ~2 GB for Wine installation
- Additional space for Wine prefixes and applications

## Dependencies

### Required Packages

Before installing Wine, ensure 32-bit architecture support is enabled:

```bash
sudo dpkg --add-architecture i386
sudo apt update
```

Install runtime dependencies:

```bash
sudo apt install -y \
    libc6:i386 \
    libx11-6:i386 libx11-6 \
    libfreetype6:i386 libfreetype6 \
    libfontconfig1:i386 libfontconfig1 \
    libxcursor1:i386 libxcursor1 \
    libxi6:i386 libxi6 \
    libxext6:i386 libxext6 \
    libxrandr2:i386 libxrandr2 \
    libxrender1:i386 libxrender1 \
    libxinerama1:i386 libxinerama1 \
    libgl1:i386 libgl1 \
    libasound2:i386 libasound2 \
    libdbus-1-3:i386 libdbus-1-3 \
    libgnutls30:i386 libgnutls30
```

See `DEPENDENCIES.txt` for complete list.

## Usage

### Running Windows Applications

```bash
# Run a Windows executable
wine /path/to/application.exe

# Or make executable and run directly
chmod +x application.exe
./application.exe
```

### Configuration

```bash
# Configure Wine settings
winecfg

# Initialize Wine prefix
wineboot

# Kill all Wine processes
wineserver -k
```

### Wine Prefixes

Wine stores Windows environment in "prefixes" (default: `~/.wine`):

```bash
# Use default prefix
wine application.exe

# Use custom prefix
export WINEPREFIX=~/.local/share/wineprefixes/app1
wine application.exe

# Create new clean prefix
WINEPREFIX=~/.wine-clean wineboot
```

## Business Central / BC4

This build includes custom locale enumeration fixes for Business Central compatibility.

### Running BC4

```bash
# Create dedicated Wine prefix
export WINEPREFIX=~/.local/share/wineprefixes/bc4
wineboot

# Run BC components
cd /path/to/bc4/
wine finsql.exe
```

### Locale Support

Custom locale data is included in `/usr/local/share/wine/nls/locale.nls` with fixes for:
- Locale enumeration stability
- Business Central locale compatibility
- Enhanced locale data processing

## Verification

### Test Installation

```bash
# Check version
wine --version

# Simple command test
wine cmd /c echo "Hello from Wine"

# Test 64-bit support
wine64 cmd /c echo "64-bit test"

# Test 32-bit support
wine cmd /c ver
```

### Verify DLLs

```bash
# Check critical DLLs exist
ls /usr/local/lib/wine/x86_64-windows/kernel32.dll
ls /usr/local/lib/wine/i386-windows/kernel32.dll

# Count installed DLLs (should be ~800-1000)
find /usr/local/lib/wine -name "*.dll" | wc -l
```

## Troubleshooting

### Wine command not found

**Check installation:**
```bash
which wine
ls -la /usr/local/bin/wine
```

**If installed to custom location, add to PATH:**
```bash
export PATH="/opt/wine-custom/bin:$PATH"
```

### Missing libraries error

**Install 32-bit libraries:**
```bash
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install libc6:i386 libx11-6:i386
```

### Application won't start

**Enable debug output:**
```bash
WINEDEBUG=+all wine application.exe 2>&1 | tee wine.log
```

**Common debug channels:**
```bash
WINEDEBUG=+locale,+reg,+httpapi wine application.exe
```

### GUI applications don't work

**Install X11 libraries:**
```bash
sudo apt install libx11-6:i386 libx11-6
```

**Check DISPLAY variable:**
```bash
echo $DISPLAY  # Should show :0 or :1
export DISPLAY=:0
```

## Uninstallation

### Using Uninstaller

```bash
# If installed with install.sh
/usr/local/bin/wine-uninstall.sh
```

### Manual Uninstall

```bash
# Remove Wine files
sudo rm -rf /usr/local/bin/wine*
sudo rm -rf /usr/local/lib/wine
sudo rm -rf /usr/local/share/wine

# Remove Wine prefixes (caution: deletes app data)
rm -rf ~/.wine
rm -rf ~/.local/share/wineprefixes
```

## Additional Resources

### Wine Configuration Files

- **System:** `/usr/local/share/wine/wine.inf`
- **User prefix:** `~/.wine/`
- **Registry:** `~/.wine/system.reg`, `~/.wine/user.reg`

### Environment Variables

```bash
# Wine prefix location
export WINEPREFIX=~/.wine

# Wine architecture (win32 or win64)
export WINEARCH=win64

# Wine debug output
export WINEDEBUG=+relay,+seh,+tid

# Disable debug output
export WINEDEBUG=-all
```

### Useful Commands

```bash
# Show Wine configuration
wine regedit

# Control Panel
wine control

# Task Manager
wine taskmgr

# Registry editor
wine regedit

# Notepad (test GUI)
wine notepad
```

## Build Information

This is a traditional dual-architecture Wine build containing:

- **64-bit Wine** - Full 64-bit Windows application support
- **32-bit Wine** - Full 32-bit Windows application support
- **Complete DLLs** - All Windows API libraries included
- **Custom patches** - Business Central locale fixes
- **Unix libraries** - Both i386 and x86_64 native support

### Package Contents

```
/usr/local/
├── bin/                    Wine executables
│   ├── wine                Main Wine binary
│   ├── wineserver          Wine server daemon
│   └── wine*               Utilities (winecfg, wineboot, etc.)
├── lib/wine/               Wine libraries and DLLs
│   ├── i386-unix/          32-bit Unix libraries (.so)
│   ├── i386-windows/       32-bit Windows DLLs (.dll)
│   ├── x86_64-unix/        64-bit Unix libraries (.so)
│   └── x86_64-windows/     64-bit Windows DLLs (.dll)
└── share/wine/             Data files
    ├── fonts/              Wine fonts
    ├── nls/                Locale data (custom fixes)
    └── wine.inf            Configuration
```

## Support

**Issues:** Report at the GitHub repository

**Debug Info:** When reporting issues, include:
```bash
wine --version
uname -a
lsb_release -a
WINEDEBUG=+all wine app.exe 2>&1 | tee wine-debug.log
```

## License

Wine is licensed under the GNU Lesser General Public License (LGPL) version 2.1 or later.

See LICENSE file or https://www.winehq.org/license for details.

## Credits

- Wine Project: https://www.winehq.org/
- Custom build for Business Central compatibility
- Includes locale enumeration fixes
