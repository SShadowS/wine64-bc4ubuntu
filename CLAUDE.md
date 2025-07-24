# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Wine (Wine Is Not an Emulator) is a compatibility layer that allows running Windows applications on Unix-like systems. This is a large, complex codebase that reimplements the Windows API.

## Building Wine

### Basic Build Commands

```bash
# Configure Wine build
./configure

# Build Wine (use -j for parallel builds)
make -j$(nproc)

# Install Wine (optional)
make install

# Run Wine directly from build directory
./wine notepad
```

### Configuration Options

Common configure options:
- `--enable-win64` - Build 64-bit Wine (won't run 32-bit binaries)
- `--without-x` - Build without X11 support
- `--with-wine64=DIR` - Build 32-bit Wine with 64-bit Wine in DIR

Run `./configure --help` for all options.

## Production Wine Build Workflow

### One-Time System Setup

**IMPORTANT**: This setup only needs to be done once per system.

```bash
# Add 32-bit architecture support
sudo dpkg --add-architecture i386

# Install core build dependencies
sudo apt update && sudo apt install -y \
  build-essential gcc-multilib g++-multilib flex bison \
  mingw-w64 ccache git

# Install Wine development libraries (64-bit)
sudo apt install -y \
  libx11-dev libfreetype-dev libxcursor-dev libxi-dev libxext-dev \
  libxrandr-dev libxinerama-dev libxcomposite-dev libxrender-dev \
  libxfixes-dev libxmu-dev libxxf86vm-dev libxss-dev libdbus-1-dev \
  libglib2.0-dev libcups2-dev libgphoto2-dev libsane-dev \
  libkrb5-dev libv4l-dev libpulse-dev libudev-dev libjpeg-dev \
  libpng-dev libtiff-dev libosmesa6-dev libgl1-mesa-dev \
  libglu1-mesa-dev libncurses-dev libpcap-dev libgnutls28-dev \
  libvulkan-dev libwayland-dev

# Install Wine development libraries (32-bit)
sudo apt install -y \
  libx11-dev:i386 libfreetype6-dev:i386 libgl1-mesa-dev:i386 \
  libglu1-mesa-dev:i386 libncurses-dev:i386 libxcursor-dev:i386 \
  libxi-dev:i386 libxrandr-dev:i386 libxcomposite-dev:i386 \
  libosmesa6-dev:i386 libdbus-1-dev:i386 libudev-dev:i386 \
  libv4l-dev:i386 libkrb5-dev:i386 libgnutls28-dev:i386 \
  libxxf86vm-dev:i386 libxinerama-dev:i386
```

### Development Build Process

**Use this workflow when testing changes or rebuilding Wine:**

```bash
cd ~/wine-source

# Create build directories (if they don't exist)
mkdir -p build/wine-64 build/wine-32

# Build 64-bit Wine
cd build/wine-64
../../configure CC="ccache gcc" CROSSCC="ccache i686-w64-mingw32-gcc" --enable-win64
make clean  # Only needed if rebuilding
make -j$(nproc)

# Build 32-bit Wine (with 64-bit support)
cd ../wine-32
../../configure CC="ccache gcc" CROSSCC="ccache i686-w64-mingw32-gcc" --with-wine64=../wine-64
make clean  # Only needed if rebuilding  
make -j$(nproc)

# Install both architectures
cd ../wine-64
sudo make install
cd ../wine-32
sudo make install
```

### Automated Build Scripts

**Use the provided build scripts for convenient development:**

```bash
# Quick incremental build and install (recommended for most changes)
./build-wine.sh

# Clean build (when you want to ensure a fresh build)
./build-wine.sh --clean

# Full reconfigure and build (when configure options change)
./build-wine.sh --full

# Quick build without install (for compilation testing)
./build-wine.sh --quick

# Test the build
./test-build.sh
```

### Manual Quick Rebuild

**Use this when you prefer manual control:**

```bash
cd ~/wine-source/build/wine-64
make -j$(nproc)
sudo make install

cd ../wine-32
make -j$(nproc)
sudo make install
```

### Performance Notes

- **ccache**: Dramatically speeds up rebuilds by caching compilation
- **Parallel builds**: `-j$(nproc)` uses all CPU cores for faster compilation
- **Separate build dirs**: Keeps source tree clean and allows easy cleanup
- **Dual architecture**: Provides full Windows compatibility (32-bit and 64-bit)

## Development Commands

### Testing

```bash
# Run all tests
make test
# or
make check

# Run tests for specific module
make dlls/kernel32/tests/test
make dlls/user32/tests/test

# Clean test results (force re-run)
make testclean

# Run individual test directly
wine dlls/kernel32/tests/x86_64-windows/kernel32_test.exe
```

### Building Individual Components

```bash
# Build specific DLL
make dlls/kernel32

# Build specific program
make programs/notepad
```

### Cleaning

```bash
# Remove intermediate files
make clean

# Remove all generated files
make distclean
```

## High-Level Architecture

### Core Components

1. **dlls/** - Windows DLL implementations
   - Each DLL reimplements Windows APIs using Unix equivalents
   - Key DLLs: ntdll, kernel32, user32, gdi32, advapi32

2. **server/** - Wine server process
   - Central authority for Windows objects and IPC
   - Manages processes, threads, synchronization, registry
   - Protocol defined in `server/protocol.def`

3. **programs/** - Wine utilities and Windows programs
   - wineserver, winecfg, regedit, cmd, notepad, etc.

4. **loader/** - PE executable loader
   - Loads and starts Windows executables

5. **tools/** - Build and development tools
   - makedep, winebuild, widl, wrc

### Key Subsystems

- **NTDLL** - Lowest level Windows subsystem, bridges to Unix
- **KERNEL32** - Core Windows APIs (files, processes, memory)
- **USER32** - Window management, input, messaging
- **GDI32** - Graphics Device Interface
- **ADVAPI32** - Security, registry, services

### How Wine Works

1. Windows executable calls Windows API
2. Wine DLL intercepts and translates the call
3. Translation layer converts to Unix/Linux equivalent
4. Results returned in Windows-compatible format

Example: `CreateFileW()` → path translation → Unix `open()` → Windows handle

### Client-Server Architecture

- Wine clients (Windows processes) communicate with wineserver
- Uses Unix domain sockets
- Server manages shared Windows objects and state

## Development Guidelines

### Code Style
- Follow existing code patterns in each module
- Windows API compatibility is paramount
- Use Wine's internal functions and macros

### Testing
- Add tests for new functionality
- Tests go in `dlls/<module>/tests/`
- Use Wine's test framework (`include/wine/test.h`)

### Common Patterns
- Unicode/ANSI function pairs (FunctionW/FunctionA)
- Handle management through wineserver
- Path translation (Windows → Unix)

## Important Files and Directories

- `include/` - Windows and Wine headers
- `include/wine/` - Wine-specific headers
- `configure.ac` - Autoconf configuration
- `server/protocol.def` - Server protocol definition
- `VERSION` - Wine version information

## Business Central Server Testing

### Wine Prefix Setup for Business Central

**Create a dedicated Wine prefix for Business Central testing:**

```bash
# Create BC testing environment
WINEPREFIX=~/.local/share/wineprefixes/bc WINEARCH=win64 wineboot -i

# Install .NET Framework 4.8 (required for BC Server)
winetricks arch=64 prefix=bc dotnet48 -q

# Install PowerShell 5.1 (if needed for BC management)
winetricks arch=64 prefix=bc ps51
```

### Testing Locale Enumeration Fix

**Test the duplicate culture fix with a simple program:**

```bash
# Compile and run locale enumeration test
cd /tmp
i686-w64-mingw32-gcc -o test_locale_enum.exe test_locale_enum.c -lkernel32
WINEPREFIX=~/.local/share/wineprefixes/bc wine test_locale_enum.exe
```

**Expected behavior after fix:**
- No duplicate "Catalan (Spain)" entries
- `ca-ES` shows as "Catalan (Spain)"
- `ca-ES-valencia` shows as "Catalan (Spain, Valencia)"

### Business Central Server Testing

**Test BC Server startup after Wine improvements:**

```bash
# Set environment for BC testing
export WINEPREFIX=~/.local/share/wineprefixes/bc
export WINEARCH=win64

# Run BC Server (adjust path as needed)
wine "C:/Program Files/Microsoft Dynamics 365 Business Central/260/Service/Microsoft.Dynamics.Nav.Server.exe"

# Monitor for culture enumeration errors
WINEDEBUG=+dll,+locale wine "BC Server executable"
```

**Common BC Server testing scenarios:**
1. **Startup test**: Verify server starts without culture exceptions
2. **HTTP API test**: Test web service functionality 
3. **Database connectivity**: Test SQL Server connections through Wine
4. **Performance monitoring**: Check for memory leaks or crashes

### Debug Channels for BC Testing

```bash
# Locale and culture debugging
WINEDEBUG=+locale,+dll wine program.exe

# HTTP API debugging  
WINEDEBUG=+httpapi,+wininet wine program.exe

# Comprehensive debugging
WINEDEBUG=+dll,+locale,+httpapi,+ole,+rpc wine program.exe

# Common debug channels: +all, +dll, +reg, +file, +process, +locale, +httpapi
```

## Debugging

```bash
# Enable debug channels
WINEDEBUG=+dll,+module wine program.exe

# Common debug channels: +all, +dll, +reg, +file, +process
```

## Contributing

See https://gitlab.winehq.org/wine/wine/-/wikis/Submitting-Patches for contribution guidelines.

Maintainers for specific areas are listed in the MAINTAINERS file.