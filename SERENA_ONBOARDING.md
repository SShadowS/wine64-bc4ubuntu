# Wine Development Onboarding Guide for Serena

Welcome to the Wine project! This guide will help you get up to speed with the Wine codebase and development workflow.

## 🎯 Project Overview

Wine (Wine Is Not an Emulator) is a compatibility layer that allows Windows applications to run on Unix-like systems. You're working on improving Wine's Windows API implementation, particularly focusing on:

- HTTP API support for Business Central Server
- Event logging functionality
- Locale and culture handling fixes

## 🏗️ Project Structure

```
wine-source/
├── dlls/           # Windows DLL implementations (main work area)
│   ├── httpapi/    # HTTP Server API (you've been fixing this)
│   ├── advapi32/   # Advanced Windows API (event logging)
│   ├── kernel32/   # Core Windows APIs
│   └── ntdll/      # NT layer (lowest level)
├── server/         # Wine server (manages Windows objects)
├── build/          # Build output directories
│   ├── wine-64/    # 64-bit Wine build
│   └── wine-32/    # 32-bit Wine build
├── include/        # Header files
└── tools/          # Build and development tools
```

## 🚀 Quick Start

### 1. Building Wine (Fastest Method)

```bash
# Use the automated build script (recommended)
./build-wine.sh

# For a clean rebuild
./build-wine.sh --clean

# Test the build
./test-build.sh
```

### 2. Manual Build (When You Need Control)

```bash
# Quick rebuild after code changes
cd ~/wine-source/build/wine-64
make -j
sudo make install

cd ../wine-32
make -j
sudo make install
```

## 🔍 Current Work & Context

### Recent Achievements
You've successfully implemented:
1. **HTTP API v2 Support** - Full implementation for Business Central
2. **Event Logging** - Environment variable-controlled logging system
3. **Locale Fixes** - Resolved duplicate display names issue
4. **BC Server Readiness Detection** - Special markers for server state

### Key Files You've Modified
- `dlls/httpapi/httpapi_main.c` - HTTP API implementation
- `dlls/advapi32/eventlog.c` - Event logging support
- `dlls/kernel32/locale.c` - Locale display name fixes
- `server/protocol.def` - Server protocol definitions

### Pending Work (from Backlog.md)
- Phase 5 performance optimizations (hash tables, red-black trees)
- HTTP/2 support
- Advanced async I/O improvements

## 🧪 Testing Workflow

### Business Central Server Testing

```bash
# 1. Set up BC environment
export WINEPREFIX=~/.local/share/wineprefixes/bc1
export WINEARCH=win64

# 2. Test BC Server startup
wine "C:/Program Files/Microsoft Dynamics 365 Business Central/260/Service/Microsoft.Dynamics.Nav.Server.exe"

# 3. Monitor for readiness
./wait_for_bc_ready.sh "wine BC_Server.exe" 60

# 4. Test HTTP functionality
./test_bc_curl.sh
```

### Event Log Testing

```bash
# Build test program
x86_64-w64-mingw32-gcc -o test_eventlog.exe test_eventlog.c

# Test with event logging enabled
WINE_EVENTLOG=1 WINEDEBUG=+eventlog wine test_eventlog.exe
```

## 🐛 Debugging Tips

### Essential Debug Channels

```bash
# HTTP API debugging
WINEDEBUG=+httpapi wine program.exe

# Event log debugging
WINEDEBUG=+eventlog wine program.exe

# Locale/culture debugging
WINEDEBUG=+locale wine program.exe

# Combined for BC Server
WINEDEBUG=+httpapi,+eventlog,+locale wine BC_Server.exe
```

### Capture Relay Logs (Advanced)

```bash
# Use memory-buffered capture for HTTP analysis
./capture_bc_relay_rg.sh

# Analyze results
rg 'HttpReceiveHttpRequest|HttpSendHttpResponse' relay_logs/bc_relay_rg_*.log
```

## 📝 Development Best Practices

### Code Style
1. **Follow existing patterns** - Each DLL has its own conventions
2. **Windows API compatibility first** - Accuracy over optimization
3. **Use Wine's internal functions** - Don't reinvent the wheel

### Testing Protocol
1. **Always test after changes** - Use `./test-build.sh`
2. **Add tests for new features** - In `dlls/<module>/tests/`
3. **Test with Business Central** - Primary use case

### Git Workflow
1. **Current branch**: `temp-patch-export-20250803_222712`
2. **Main branch**: `master` (for PRs)
3. **Never commit unless asked** - User prefers explicit control

## 🔧 Common Tasks

### Rebuilding After Changes

```bash
# Quick rebuild (most common)
./build-wine.sh

# Just compile without install
./build-wine.sh --quick
```

### Finding Functions

```bash
# Search for function implementations
grep -r "HttpReceiveHttpRequest" dlls/

# Find where a Windows API is implemented
grep -r "WINAPI CreateFileW" dlls/
```

### Checking Your Changes

```bash
# See what you've modified
git status
git diff

# Check specific file history
git log -p dlls/httpapi/httpapi_main.c
```

## 🎯 Key Areas to Focus On

1. **HTTP API (dlls/httpapi/)** - Business Central's web services
2. **Event Logging (dlls/advapi32/)** - Service diagnostics
3. **Server Protocol (server/)** - Wine server communication
4. **Locale Handling (dlls/kernel32/)** - Culture enumeration

## 📚 Resources

- **CLAUDE.md** - AI assistant instructions (you're reading a summary)
- **Backlog.md** - Pending features and optimizations
- **PLAN*.md files** - Implementation plans for various phases
- **Test scripts** - `test_*.sh` files for automated testing

## 💡 Pro Tips

1. **Use ccache** - Already configured, speeds up rebuilds dramatically
2. **Parallel builds** - `-j` flag uses all CPU cores
3. **Separate build dirs** - Keeps source clean, easy cleanup
4. **Debug channels** - Your best friend for troubleshooting
5. **BC readiness markers** - Watch for "SERVER READY" messages

## 🚨 Common Issues & Solutions

### Build Fails
```bash
# Clean and rebuild
./build-wine.sh --clean
```

### BC Server Won't Start
```bash
# Check with debug output
WINEDEBUG=+httpapi,+dll wine BC_Server.exe 2>&1 | tee bc_debug.log
```

### Changes Not Taking Effect
```bash
# Ensure you're installing after building
cd build/wine-64 && sudo make install
cd ../wine-32 && sudo make install
```

## 📞 Getting Help

- Check existing documentation: `CLAUDE.md`, `Backlog.md`
- Review test scripts for examples
- Use debug channels to understand flow
- Git history shows what worked before

---

Welcome aboard! You're joining a project that's making significant improvements to Wine's Windows compatibility layer. Your recent work on HTTP APIs and event logging has been crucial for Business Central support.