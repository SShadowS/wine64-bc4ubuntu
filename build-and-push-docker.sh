#!/bin/bash
# Build and push Wine Docker image to registry

set -e

# Start timing
SCRIPT_START_TIME=$SECONDS

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
WINE_VERSION="${WINE_VERSION:-10.15}"
BUILD_DATE=$(date +%Y%m%d)
RUNTIME_HISTORY_FILE=".build_runtime_history"

# Parse command line arguments
DOCKER_USERNAME=""
REGISTRY="docker.io"  # Default to Docker Hub
PUSH_TO_DOCKERHUB=false
PUSH_TO_GHCR=false
NO_CACHE=false

print_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -u, --username USERNAME    Docker Hub username"
    echo "  -g, --github USERNAME      GitHub username for ghcr.io"
    echo "  -d, --dockerhub           Push to Docker Hub"
    echo "  -r, --ghcr                Push to GitHub Container Registry"
    echo "  -f, --flavor FLAVOR       Base image flavor: ubuntu (default), debian, or alpine"
    echo "  -n, --no-cache            Build without cache"
    echo "  -h, --help                Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  DOCKER_USERNAME           Docker Hub username"
    echo "  GITHUB_USERNAME           GitHub username"
    echo "  GITHUB_TOKEN             GitHub token for ghcr.io"
    echo "  DOCKERFILE                Dockerfile to use (default: Dockerfile.source)"
    echo ""
    echo "Examples:"
    echo "  $0 -u myuser -d           # Build and push to Docker Hub (Ubuntu)"
    echo "  $0 -f debian -g myuser -r # Build Debian variant and push to ghcr.io"
    echo "  $0 -u myuser -d -r        # Push to both registries"
}

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Format seconds into human-readable duration
format_duration() {
    local total_seconds=$1
    local hours=$((total_seconds / 3600))
    local minutes=$(((total_seconds % 3600) / 60))
    local seconds=$((total_seconds % 60))

    if [ $hours -gt 0 ]; then
        printf "%dh %dm %ds" $hours $minutes $seconds
    elif [ $minutes -gt 0 ]; then
        printf "%dm %ds" $minutes $seconds
    else
        printf "%ds" $seconds
    fi
}

# Load runtime history
load_runtime_history() {
    if [ -f "$RUNTIME_HISTORY_FILE" ]; then
        cat "$RUNTIME_HISTORY_FILE" 2>/dev/null || echo "[]"
    else
        echo "[]"
    fi
}

# Save runtime record (keep only last 3)
save_runtime_record() {
    local duration=$1
    local flavor=$2
    local no_cache=$3
    local push_dockerhub=$4
    local push_ghcr=$5

    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local new_record=$(cat <<EOF
{
  "timestamp": "$timestamp",
  "duration": $duration,
  "flavor": "$flavor",
  "no_cache": $no_cache,
  "push_dockerhub": $push_dockerhub,
  "push_ghcr": $push_ghcr
}
EOF
)

    # Load existing history
    local history=$(load_runtime_history)

    # Add new record and keep only last 3
    local updated_history=$(echo "$history" | jq --argjson new "$new_record" '. + [$new] | .[-3:]' 2>/dev/null)

    if [ $? -eq 0 ] && [ -n "$updated_history" ]; then
        echo "$updated_history" > "$RUNTIME_HISTORY_FILE"
    else
        # Fallback if jq fails: simple append (no JSON)
        echo "$new_record" >> "$RUNTIME_HISTORY_FILE"
    fi
}

# Display runtime statistics from history
display_runtime_stats() {
    if [ ! -f "$RUNTIME_HISTORY_FILE" ]; then
        return
    fi

    local history=$(load_runtime_history)
    local count=$(echo "$history" | jq 'length' 2>/dev/null)

    if [ $? -ne 0 ] || [ -z "$count" ] || [ "$count" -eq 0 ]; then
        return
    fi

    # Calculate average duration
    local total_duration=$(echo "$history" | jq '[.[].duration] | add' 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$total_duration" ]; then
        local avg_duration=$((total_duration / count))
        echo ""
        echo "=================================="
        print_status "Previous builds (last $count run(s)):"
        echo "$history" | jq -r '.[] | "  \(.timestamp | split("T")[0]) - \(.flavor) - Duration: \(.duration)s - No-cache: \(.no_cache) - Push: DH=\(.push_dockerhub), GHCR=\(.push_ghcr)"' 2>/dev/null
        print_status "Average runtime: $(format_duration $avg_duration)"
        echo "=================================="
        echo ""
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--username)
            DOCKER_USERNAME="$2"
            shift 2
            ;;
        -g|--github)
            GITHUB_USERNAME="$2"
            shift 2
            ;;
        -d|--dockerhub)
            PUSH_TO_DOCKERHUB=true
            shift
            ;;
        -r|--ghcr)
            PUSH_TO_GHCR=true
            shift
            ;;
        -f|--flavor)
            FLAVOR="$2"
            shift 2
            ;;
        -n|--no-cache)
            NO_CACHE=true
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

# Handle flavor selection
FLAVOR="${FLAVOR:-ubuntu}"
if [ "$FLAVOR" = "alpine" ]; then
    DOCKERFILE="${DOCKERFILE:-Dockerfile.alpine}"
    IMAGE_NAME="${IMAGE_NAME:-wine-bc-alpine}"
elif [ "$FLAVOR" = "ubuntu" ]; then
    DOCKERFILE="${DOCKERFILE:-Dockerfile.source}"
    IMAGE_NAME="${IMAGE_NAME:-wine-bc}"
elif [ "$FLAVOR" = "debian" ]; then
    DOCKERFILE="${DOCKERFILE:-Dockerfile.debian}"
    IMAGE_NAME="${IMAGE_NAME:-wine-bc-debian}"
else
    print_error "Invalid flavor: $FLAVOR (must be 'ubuntu', 'debian', or 'alpine')"
    exit 1
fi

# Check if we have required credentials
if [ "$PUSH_TO_DOCKERHUB" = true ] && [ -z "$DOCKER_USERNAME" ]; then
    print_error "Docker Hub username required for pushing to Docker Hub"
    exit 1
fi

if [ "$PUSH_TO_GHCR" = true ]; then
    if [ -z "$GITHUB_USERNAME" ]; then
        print_error "GitHub username required for pushing to ghcr.io"
        exit 1
    fi
    if [ -z "$GITHUB_TOKEN" ]; then
        print_warning "GITHUB_TOKEN not set. You'll need to login manually to ghcr.io"
    fi
fi

# Build flags
BUILD_FLAGS=""
if [ "$NO_CACHE" = true ]; then
    BUILD_FLAGS="--no-cache"
fi

# Display runtime statistics from previous runs
display_runtime_stats

print_status "Building Wine Docker image..."
print_status "Flavor: $FLAVOR"
print_status "Dockerfile: $DOCKERFILE"
print_status "Image name: $IMAGE_NAME"
print_status "Wine version: $WINE_VERSION"

# Build the image
echo ""
print_status "Starting Docker build..."
docker build $BUILD_FLAGS -f "$DOCKERFILE" -t "${IMAGE_NAME}:build" . || {
    print_error "Docker build failed!"
    exit 1
}

print_success "Docker build completed!"

# Get image size
IMAGE_SIZE=$(docker images "${IMAGE_NAME}:build" --format "{{.Size}}")
print_status "Image size: $IMAGE_SIZE"

# Test the image
print_status "Testing Wine installation..."
docker run --rm "${IMAGE_NAME}:build" wine --version || {
    print_error "Wine test failed!"
    exit 1
}

docker run --rm "${IMAGE_NAME}:build" wine64 --version || {
    print_error "Wine64 test failed!"
    exit 1
}

print_success "Wine tests passed!"

# Push to Docker Hub
if [ "$PUSH_TO_DOCKERHUB" = true ]; then
    print_status "Pushing to Docker Hub..."

    # Check if logged in
    if ! docker info 2>/dev/null | grep -q "Username: ${DOCKER_USERNAME}"; then
        print_status "Logging in to Docker Hub..."
        docker login || {
            print_error "Docker Hub login failed!"
            exit 1
        }
    fi

    # Tag images
    docker tag "${IMAGE_NAME}:build" "${DOCKER_USERNAME}/${IMAGE_NAME}:latest"
    docker tag "${IMAGE_NAME}:build" "${DOCKER_USERNAME}/${IMAGE_NAME}:${WINE_VERSION}"
    docker tag "${IMAGE_NAME}:build" "${DOCKER_USERNAME}/${IMAGE_NAME}:${WINE_VERSION}-${BUILD_DATE}"

    # Push images
    docker push "${DOCKER_USERNAME}/${IMAGE_NAME}:latest" || {
        print_error "Failed to push to Docker Hub!"
        exit 1
    }
    docker push "${DOCKER_USERNAME}/${IMAGE_NAME}:${WINE_VERSION}"
    docker push "${DOCKER_USERNAME}/${IMAGE_NAME}:${WINE_VERSION}-${BUILD_DATE}"

    print_success "Pushed to Docker Hub!"
    print_status "Images available at:"
    echo "  docker pull ${DOCKER_USERNAME}/${IMAGE_NAME}:latest"
    echo "  docker pull ${DOCKER_USERNAME}/${IMAGE_NAME}:${WINE_VERSION}"
    echo ""
fi

# Push to GitHub Container Registry
if [ "$PUSH_TO_GHCR" = true ]; then
    print_status "Pushing to GitHub Container Registry..."

    # Login to ghcr.io
    if [ -n "$GITHUB_TOKEN" ]; then
        echo "$GITHUB_TOKEN" | docker login ghcr.io -u "$GITHUB_USERNAME" --password-stdin || {
            print_error "GitHub Container Registry login failed!"
            exit 1
        }
    else
        print_warning "Please login to ghcr.io manually:"
        echo "echo \$GITHUB_TOKEN | docker login ghcr.io -u $GITHUB_USERNAME --password-stdin"
        exit 1
    fi

    # Tag images for ghcr.io
    docker tag "${IMAGE_NAME}:build" "ghcr.io/${GITHUB_USERNAME}/${IMAGE_NAME}:latest"
    docker tag "${IMAGE_NAME}:build" "ghcr.io/${GITHUB_USERNAME}/${IMAGE_NAME}:${WINE_VERSION}"
    docker tag "${IMAGE_NAME}:build" "ghcr.io/${GITHUB_USERNAME}/${IMAGE_NAME}:${WINE_VERSION}-${BUILD_DATE}"

    # Push to ghcr.io
    docker push "ghcr.io/${GITHUB_USERNAME}/${IMAGE_NAME}:latest" || {
        print_error "Failed to push to ghcr.io!"
        exit 1
    }
    docker push "ghcr.io/${GITHUB_USERNAME}/${IMAGE_NAME}:${WINE_VERSION}"
    docker push "ghcr.io/${GITHUB_USERNAME}/${IMAGE_NAME}:${WINE_VERSION}-${BUILD_DATE}"

    print_success "Pushed to GitHub Container Registry!"
    print_status "Images available at:"
    echo "  docker pull ghcr.io/${GITHUB_USERNAME}/${IMAGE_NAME}:latest"
    echo "  docker pull ghcr.io/${GITHUB_USERNAME}/${IMAGE_NAME}:${WINE_VERSION}"
    echo ""
fi

# Clean up local build tag
docker rmi "${IMAGE_NAME}:build" 2>/dev/null || true

# Calculate runtime and save to history
SCRIPT_END_TIME=$SECONDS
SCRIPT_DURATION=$((SCRIPT_END_TIME - SCRIPT_START_TIME))
save_runtime_record "$SCRIPT_DURATION" "$FLAVOR" "$NO_CACHE" "$PUSH_TO_DOCKERHUB" "$PUSH_TO_GHCR"

print_success "All operations completed successfully!"

# Show summary
echo ""
echo "=================================="
echo "         BUILD SUMMARY            "
echo "=================================="
echo "Flavor:           $FLAVOR"
echo "Image name:       $IMAGE_NAME"
echo "Wine version:     $WINE_VERSION"
echo "Image size:       $IMAGE_SIZE"
echo "Build date:       $BUILD_DATE"
echo "Runtime:          $(format_duration $SCRIPT_DURATION)"

if [ "$PUSH_TO_DOCKERHUB" = true ]; then
    echo ""
    echo "Docker Hub:"
    echo "  ${DOCKER_USERNAME}/${IMAGE_NAME}:latest"
    echo "  ${DOCKER_USERNAME}/${IMAGE_NAME}:${WINE_VERSION}"
fi

if [ "$PUSH_TO_GHCR" = true ]; then
    echo ""
    echo "GitHub Container Registry:"
    echo "  ghcr.io/${GITHUB_USERNAME}/${IMAGE_NAME}:latest"
    echo "  ghcr.io/${GITHUB_USERNAME}/${IMAGE_NAME}:${WINE_VERSION}"
fi

echo "=================================="