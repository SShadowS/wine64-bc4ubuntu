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

## Debugging

```bash
# Enable debug channels
WINEDEBUG=+dll,+module wine program.exe

# Common debug channels: +all, +dll, +reg, +file, +process
```

## Contributing

See https://gitlab.winehq.org/wine/wine/-/wikis/Submitting-Patches for contribution guidelines.

Maintainers for specific areas are listed in the MAINTAINERS file.