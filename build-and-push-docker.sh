#!/bin/bash
# Build and push Wine Docker image to registry

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
DOCKERFILE="${DOCKERFILE:-Dockerfile.source}"
IMAGE_NAME="${IMAGE_NAME:-wine-bc4}"
WINE_VERSION="${WINE_VERSION:-10.15}"
BUILD_DATE=$(date +%Y%m%d)

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
    echo "  -n, --no-cache            Build without cache"
    echo "  -h, --help                Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  DOCKER_USERNAME           Docker Hub username"
    echo "  GITHUB_USERNAME           GitHub username"
    echo "  GITHUB_TOKEN             GitHub token for ghcr.io"
    echo ""
    echo "Examples:"
    echo "  $0 -u myuser -d           # Build and push to Docker Hub"
    echo "  $0 -g myuser -r           # Build and push to ghcr.io"
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

print_status "Building Wine Docker image..."
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

print_success "All operations completed successfully!"

# Show summary
echo ""
echo "=================================="
echo "         BUILD SUMMARY            "
echo "=================================="
echo "Image name:       $IMAGE_NAME"
echo "Wine version:     $WINE_VERSION"
echo "Image size:       $IMAGE_SIZE"
echo "Build date:       $BUILD_DATE"

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