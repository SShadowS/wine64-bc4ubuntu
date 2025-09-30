#!/bin/bash
# Wine Custom Build - Release Preparation Script
# Automates version bumping, changelog generation, and release validation

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHANGELOG_FILE="$REPO_ROOT/CHANGELOG.md"
VERSION_FILE="$REPO_ROOT/VERSION"

print_header() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  $1"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}\n"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Show usage
show_usage() {
    cat << EOF
Wine Custom Build - Release Preparation Tool

Usage: $0 [OPTIONS]

Options:
    --version VERSION    Specify release version (e.g., 10.15-custom)
    --auto              Automatically determine version from Wine
    --check             Check release readiness without making changes
    --tag-only          Only create and push git tag
    --help              Show this help message

Examples:
    # Prepare release with specific version
    $0 --version 10.15-custom

    # Auto-detect Wine version
    $0 --auto

    # Check readiness without changes
    $0 --check

    # Just create and push tag
    $0 --tag-only --version 10.15-custom

Workflow:
    1. Validates repository state (no uncommitted changes)
    2. Determines version number
    3. Updates CHANGELOG.md with recent commits
    4. Creates version tag
    5. Optionally pushes to remote (triggering CI/CD)

EOF
}

# Check if we're in a git repository
check_git_repo() {
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        print_error "Not a git repository"
        exit 1
    fi
    print_success "Git repository detected"
}

# Check for uncommitted changes
check_working_tree() {
    if ! git diff-index --quiet HEAD -- 2>/dev/null; then
        print_warning "Working tree has uncommitted changes"
        git status --short
        echo ""
        read -p "Continue anyway? (yes/no) " -r
        if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            print_info "Aborted by user"
            exit 0
        fi
    else
        print_success "Working tree is clean"
    fi
}

# Get Wine version from source
get_wine_version() {
    if [ -f "$REPO_ROOT/VERSION" ]; then
        cat "$REPO_ROOT/VERSION"
    elif [ -f "$REPO_ROOT/configure.ac" ]; then
        grep "AC_INIT" "$REPO_ROOT/configure.ac" | sed -n 's/.*wine.*\[\([0-9.]*\)\].*/\1/p' | head -1
    else
        echo "unknown"
    fi
}

# Generate changelog from git commits
generate_changelog_entry() {
    local version=$1
    local since_tag=$2
    local date=$(date '+%Y-%m-%d')

    echo ""
    echo "## [$version] - $date"
    echo ""

    # Get commits since last tag
    if [ -n "$since_tag" ]; then
        print_info "Generating changelog since $since_tag"
        local commits=$(git log ${since_tag}..HEAD --pretty=format:"- %s" --no-merges)
    else
        print_info "Generating changelog for recent commits"
        local commits=$(git log --pretty=format:"- %s" --no-merges -n 20)
    fi

    # Categorize commits
    echo "### Added"
    echo "$commits" | grep -i "^- \(add\|new\|feat\)" || echo "- No new features"
    echo ""

    echo "### Changed"
    echo "$commits" | grep -i "^- \(change\|update\|improve\)" || echo "- No changes"
    echo ""

    echo "### Fixed"
    echo "$commits" | grep -i "^- \(fix\|bugfix\|patch\)" || echo "- No fixes"
    echo ""
}

# Update CHANGELOG.md
update_changelog() {
    local version=$1

    print_info "Updating CHANGELOG.md"

    # Get last release tag
    local last_tag=$(git describe --tags --abbrev=0 2>/dev/null || echo "")

    # Generate new entry
    local new_entry=$(generate_changelog_entry "$version" "$last_tag")

    # Create or update CHANGELOG.md
    if [ -f "$CHANGELOG_FILE" ]; then
        # Insert new entry after header
        local temp_file=$(mktemp)
        if grep -q "^# Changelog" "$CHANGELOG_FILE"; then
            # Has header, insert after it
            sed '/^# Changelog/r '<(echo "$new_entry") "$CHANGELOG_FILE" > "$temp_file"
        else
            # No header, add one
            echo "# Changelog" > "$temp_file"
            echo "" >> "$temp_file"
            echo "All notable changes to this project will be documented in this file." >> "$temp_file"
            echo "$new_entry" >> "$temp_file"
            echo "" >> "$temp_file"
            cat "$CHANGELOG_FILE" >> "$temp_file"
        fi
        mv "$temp_file" "$CHANGELOG_FILE"
    else
        # Create new CHANGELOG.md
        cat > "$CHANGELOG_FILE" << EOF
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

$new_entry
EOF
    fi

    print_success "CHANGELOG.md updated"
}

# Create git tag
create_release_tag() {
    local version=$1
    local tag_name="release-${version}"

    print_info "Creating release tag: $tag_name"

    # Check if tag already exists
    if git rev-parse "$tag_name" >/dev/null 2>&1; then
        print_warning "Tag $tag_name already exists"
        read -p "Delete existing tag and recreate? (yes/no) " -r
        if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            git tag -d "$tag_name"
            git push origin ":refs/tags/$tag_name" 2>/dev/null || true
            print_info "Deleted existing tag"
        else
            print_error "Tag already exists, aborting"
            exit 1
        fi
    fi

    # Create annotated tag
    local tag_message="Wine Custom Build v${version}

Release includes:
- Complete Wine installation (64-bit + 32-bit)
- Custom locale fixes for Business Central
- All Windows DLLs and Unix libraries
- Professional packaging (.tar.gz + .deb)

Built on $(date '+%Y-%m-%d %H:%M:%S %Z')
"

    git tag -a "$tag_name" -m "$tag_message"
    print_success "Tag created: $tag_name"

    return 0
}

# Check release readiness
check_release_readiness() {
    local issues=0

    print_header "Release Readiness Check"

    # Check 1: Git repository
    if git rev-parse --git-dir > /dev/null 2>&1; then
        print_success "Git repository: OK"
    else
        print_error "Not a git repository"
        ((issues++))
    fi

    # Check 2: Required files
    for file in "configure.ac" "Dockerfile.release" "docker/build-in-container.sh"; do
        if [ -f "$REPO_ROOT/$file" ]; then
            print_success "Required file: $file"
        else
            print_error "Missing file: $file"
            ((issues++))
        fi
    done

    # Check 3: Release files
    if [ -d "$REPO_ROOT/release-files" ]; then
        print_success "Release files directory exists"
        for file in "install.sh" "README.md" "DEPENDENCIES.txt"; do
            if [ -f "$REPO_ROOT/release-files/$file" ]; then
                print_success "  ├─ $file"
            else
                print_error "  ├─ Missing: $file"
                ((issues++))
            fi
        done
    else
        print_error "Release files directory missing"
        ((issues++))
    fi

    # Check 4: Debian package files
    if [ -d "$REPO_ROOT/debian-package" ]; then
        print_success "Debian package directory exists"
    else
        print_warning "Debian package directory missing (optional)"
    fi

    # Check 5: GitHub Actions workflow
    if [ -f "$REPO_ROOT/.github/workflows/release.yml" ]; then
        print_success "GitHub Actions workflow exists"
    else
        print_error "GitHub Actions workflow missing"
        ((issues++))
    fi

    # Check 6: Working tree clean
    if git diff-index --quiet HEAD -- 2>/dev/null; then
        print_success "Working tree is clean"
    else
        print_warning "Working tree has uncommitted changes"
    fi

    # Check 7: Remote configured
    if git remote get-url origin >/dev/null 2>&1; then
        print_success "Git remote configured: $(git remote get-url origin)"
    else
        print_warning "No git remote configured"
    fi

    echo ""
    if [ $issues -eq 0 ]; then
        print_success "All checks passed! Ready to release."
        return 0
    else
        print_error "$issues issue(s) found. Please fix before releasing."
        return 1
    fi
}

# Main function
main() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║     Wine Custom Build - Release Preparation Tool                 ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""

    # Parse arguments
    VERSION=""
    AUTO_VERSION=false
    CHECK_ONLY=false
    TAG_ONLY=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --version)
                VERSION="$2"
                shift 2
                ;;
            --auto)
                AUTO_VERSION=true
                shift
                ;;
            --check)
                CHECK_ONLY=true
                shift
                ;;
            --tag-only)
                TAG_ONLY=true
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

    # Check only mode
    if [ "$CHECK_ONLY" = true ]; then
        check_release_readiness
        exit $?
    fi

    # Basic checks
    check_git_repo

    # Determine version
    if [ -z "$VERSION" ]; then
        if [ "$AUTO_VERSION" = true ]; then
            WINE_VER=$(get_wine_version)
            GIT_DESC=$(git describe --always --dirty 2>/dev/null || echo "custom")
            VERSION="${WINE_VER}-${GIT_DESC}"
            print_info "Auto-detected version: $VERSION"
        else
            print_error "Version not specified. Use --version or --auto"
            show_usage
            exit 1
        fi
    fi

    print_header "Preparing Release: $VERSION"

    # Check working tree
    if [ "$TAG_ONLY" != true ]; then
        check_working_tree
    fi

    # Tag only mode
    if [ "$TAG_ONLY" = true ]; then
        create_release_tag "$VERSION"

        echo ""
        print_info "Tag created. Push to remote to trigger release build:"
        echo ""
        echo "  git push origin release-${VERSION}"
        echo ""
        exit 0
    fi

    # Full release preparation
    print_header "Updating Project Files"

    # Update CHANGELOG
    update_changelog "$VERSION"

    # Show what changed
    if [ -f "$CHANGELOG_FILE" ]; then
        echo ""
        print_info "Preview of CHANGELOG.md:"
        head -30 "$CHANGELOG_FILE"
        echo ""
    fi

    # Confirm changes
    print_warning "Review the changes above"
    read -p "Commit changes and create release tag? (yes/no) " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        print_info "Aborted by user"
        exit 0
    fi

    # Commit changes
    if ! git diff-index --quiet HEAD -- 2>/dev/null; then
        print_info "Committing changes"
        git add "$CHANGELOG_FILE"
        git commit -m "Prepare release ${VERSION}

- Update CHANGELOG.md
- Release version: ${VERSION}"
        print_success "Changes committed"
    fi

    # Create tag
    create_release_tag "$VERSION"

    # Final instructions
    print_header "Release Prepared Successfully!"

    echo "Next steps:"
    echo ""
    echo "1. Push commit and tag to trigger release:"
    echo "   ${GREEN}git push origin master${NC}"
    echo "   ${GREEN}git push origin release-${VERSION}${NC}"
    echo ""
    echo "2. GitHub Actions will automatically:"
    echo "   - Build Wine in Docker"
    echo "   - Run tests"
    echo "   - Create packages (.tar.gz + .deb)"
    echo "   - Create GitHub Release"
    echo "   - Upload packages as assets"
    echo ""
    echo "3. Monitor build progress:"
    echo "   https://github.com/$(git remote get-url origin | sed 's/.*github.com[:/]\(.*\)\.git/\1/')/actions"
    echo ""

    read -p "Push to remote now? (yes/no) " -r
    if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        print_info "Pushing to remote"
        git push origin master
        git push origin "release-${VERSION}"
        echo ""
        print_success "Release initiated! Check GitHub Actions for build progress."
    else
        print_info "Remember to push manually when ready"
    fi
}

# Run main
main "$@"
