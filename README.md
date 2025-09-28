# Wine 64-bit for Business Central on Ubuntu

Wine fork with patches to support Microsoft Dynamics 365 Business Central Server on Ubuntu Linux.

## About

This is a modified version of Wine that includes patches specifically designed to run Microsoft Dynamics 365 Business Central Server on Ubuntu. The standard Wine distribution has several compatibility issues that prevent BC Server from functioning correctly. This fork addresses those issues.

Based on Wine 10.14 from [wine-mirror/wine](https://github.com/wine-mirror/wine).

Wine is free software, released under the GNU LGPL; see the file LICENSE for the details.

## Business Central Patches

- **WebSocket over TLS (WSS)** implementation with NTLM authentication bypass
- **HTTP.sys async I/O** completion fixes for BC Server
- **Locale/culture enumeration** fixes to prevent duplicate culture crashes
- **Event logging** support for BC diagnostics
- **Server readiness** detection markers for automated testing
- **Automatic locale.nls** regeneration in build process


## Quick Start

### Building

Use the provided build script for convenient development:

```bash
# Quick incremental build and install (recommended)
./build-wine.sh

# Clean build
./build-wine.sh --clean

# Full reconfigure and build
./build-wine.sh --full

# Quick build without install (for compilation testing)
./build-wine.sh --quick
```

Or manually:

```bash
# From the top-level directory
cd build/wine-64
../../configure CC="ccache gcc" CROSSCC="ccache i686-w64-mingw32-gcc" --enable-win64
make -j
sudo make install

cd ../wine-32
../../configure CC="ccache gcc" CROSSCC="ccache i686-w64-mingw32-gcc" --with-wine64=../wine-64
make -j
sudo make install
```

### Testing with Business Central

```bash
# Set Wine prefix for BC
export WINEPREFIX=~/.local/share/wineprefixes/bc1
export WINEARCH=win64

# Run BC Server
wine "C:/Program Files/Microsoft Dynamics 365 Business Central/260/Service/Microsoft.Dynamics.Nav.Server.exe"

# With debug output
WINEDEBUG=+httpapi,+websocket wine "C:/Program Files/Microsoft Dynamics 365 Business Central/260/Service/Microsoft.Dynamics.Nav.Server.exe"
```

## Status

✅ **Working** - Business Central Server successfully running on Wine/Ubuntu with WebSocket support

**Active Branch**: `wss-implementation-poc` - Contains all BC Server compatibility fixes

**Tested With**: Microsoft Dynamics 365 Business Central Version 26.0

## Requirements

To compile and run Wine, you must have one of the following:

- Linux version 2.6.22 or later
- FreeBSD 12.4 or later
- Solaris x86 9 or later
- NetBSD-current
- macOS 10.12 or later

As Wine requires kernel-level thread support to run, only the operating
systems mentioned above are supported.  Other operating systems which
support kernel threads may be supported in the future.

**FreeBSD info**:
  See https://wiki.freebsd.org/Wine for more information.

**Solaris info**:
  You will most likely need to build Wine with the GNU toolchain
  (gcc, gas, etc.). Warning : installing gas does *not* ensure that it
  will be used by gcc. Recompiling gcc after installing gas or
  symlinking cc, as and ld to the gnu tools is said to be necessary.

**NetBSD info**:
  Make sure you have the USER_LDT, SYSVSHM, SYSVSEM, and SYSVMSG options
  turned on in your kernel.

**macOS info**:
  You need Xcode/Xcode Command Line Tools or Apple cctools.  The
  minimum requirements for compiling Wine are clang 3.8 with the
  MacOSX10.13.sdk and mingw-w64 v12 for 32-bit wine.  The
  MacOSX10.14.sdk and later can build 64-bit wine.

**Supported file systems**:
  Wine should run on most file systems. A few compatibility problems
  have also been reported using files accessed through Samba. Also,
  NTFS does not provide all the file system features needed by some
  applications.  Using a native Unix file system is recommended.

**Basic requirements**:
  You need to have the X11 development include files installed
  (called xorg-dev in Debian and libX11-devel in Red Hat).
  Of course you also need make (most likely GNU make).
  You also need flex version 2.5.33 or later and bison.

**Optional support libraries**:
  Configure will display notices when optional libraries are not found
  on your system. See https://gitlab.winehq.org/wine/wine/-/wikis/Building-Wine
  for hints about the packages you should install. On 64-bit
  platforms, you have to make sure to install the 32-bit versions of
  these libraries.


## COMPILATION

To build Wine, do:

```
./configure
make
```

This will build the program "wine" and numerous support libraries/binaries.
The program "wine" will load and run Windows executables.
The library "libwine" ("Winelib") can be used to compile and link
Windows source code under Unix.

To see compile configuration options, do `./configure --help`.

For more information, see https://gitlab.winehq.org/wine/wine/-/wikis/Building-Wine


## SETUP

Once Wine has been built correctly, you can do `make install`; this
will install the wine executable and libraries, the Wine man page, and
other needed files.

Don't forget to uninstall any conflicting previous Wine installation
first.  Try either `dpkg -r wine` or `rpm -e wine` or `make uninstall`
before installing.

Once installed, you can run the `winecfg` configuration tool. See the
Support area at https://www.winehq.org/ for configuration hints.


## RUNNING PROGRAMS

When invoking Wine, you may specify the entire path to the executable,
or a filename only.

For example, to run Notepad:

```
wine notepad            (using the search Path as specified in
wine notepad.exe         the registry to locate the file)

wine c:\\windows\\notepad.exe      (using DOS filename syntax)

wine ~/.wine/drive_c/windows/notepad.exe  (using Unix filename syntax)

wine notepad.exe readme.txt          (calling program with parameters)
```

Wine is not perfect, so some programs may crash. If that happens you
will get a crash log that you should attach to your report when filing
a bug.


## GETTING MORE INFORMATION

- **WWW**: A great deal of information about Wine is available from WineHQ at
	https://www.winehq.org/ : various Wine Guides, application database,
	bug tracking. This is probably the best starting point.

- **FAQ**: The Wine FAQ is located at https://gitlab.winehq.org/wine/wine/-/wikis/FAQ

- **Wiki**: The Wine Wiki is located at https://gitlab.winehq.org/wine/wine/-/wikis/

- **Gitlab**: Wine development is hosted at https://gitlab.winehq.org

- **Mailing lists**:
	There are several mailing lists for Wine users and developers; see
	https://gitlab.winehq.org/wine/wine/-/wikis/Forums for more
	information.

- **Bugs**: Report bugs to Wine Bugzilla at https://bugs.winehq.org
	Please search the bugzilla database to check whether your
	problem is already known or fixed before posting a bug report.

- **IRC**: Online help is available at channel `#WineHQ` on irc.libera.chat.
