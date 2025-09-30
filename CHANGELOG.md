# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project uses Wine version numbers with custom suffixes.

## [Unreleased]

### Added
- Release automation system with version management
- .deb package support for Debian/Ubuntu
- Comprehensive testing suite (6 levels + smoke tests)
- Interactive installer with dependency checking
- Docker-based reproducible builds
- GitHub Actions CI/CD workflow
- Complete user and developer documentation

### Changed
- Traditional dual-architecture build method for maximum compatibility
- Custom locale enumeration fixes for Business Central

### Fixed
- Locale data processing for BC4 compatibility

## [10.15-initial] - 2025-09-30

### Added
- Initial Wine custom build setup
- Business Central locale fixes
- Custom make_unicode processing

---

## How to Update This Changelog

### For Developers

When preparing a release, use the `prepare-release.sh` script:

```bash
./prepare-release.sh --auto
```

This will automatically:
1. Extract commits since last release
2. Categorize them (Added/Changed/Fixed)
3. Create a new changelog entry
4. Commit changes

### Manual Updates

Follow this format:

```markdown
## [VERSION] - YYYY-MM-DD

### Added
- New features or capabilities

### Changed
- Changes to existing functionality

### Deprecated
- Features planned for removal

### Removed
- Removed features

### Fixed
- Bug fixes

### Security
- Security vulnerability fixes
```

### Commit Message Guidelines

To help with automatic changelog generation, use prefixes:

- `add:` or `feat:` - New features → "Added" section
- `change:` or `update:` - Modifications → "Changed" section
- `fix:` or `bugfix:` - Bug fixes → "Fixed" section
- `remove:` - Removed features → "Removed" section
- `security:` - Security fixes → "Security" section

Example:
```
add: .deb package support for Ubuntu 22.04
fix: locale enumeration crash in BC4
update: GitHub Actions workflow with testing
```
