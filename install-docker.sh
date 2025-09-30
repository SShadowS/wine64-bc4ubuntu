#!/bin/bash
set -e

echo "=== Docker Installation Script for Ubuntu ==="
echo ""

# Step 1: Update existing packages
echo "Step 1: Updating existing packages..."
sudo apt update

# Step 2: Install prerequisite packages
echo ""
echo "Step 2: Installing prerequisite packages..."
sudo apt install -y ca-certificates curl gnupg

# Step 3: Add Docker's official GPG key
echo ""
echo "Step 3: Adding Docker's official GPG key..."
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Step 4: Set up Docker repository
echo ""
echo "Step 4: Setting up Docker repository..."
echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Step 5: Update package index again
echo ""
echo "Step 5: Updating package index..."
sudo apt update

# Step 6: Install Docker packages
echo ""
echo "Step 6: Installing Docker packages..."
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Step 7: Verify installation
echo ""
echo "Step 7: Verifying Docker installation..."
sudo docker run hello-world

echo ""
echo "=== Docker installation completed successfully! ==="
echo ""
echo "Optional: To run Docker without sudo, add your user to the docker group:"
echo "  sudo usermod -aG docker \$USER"
echo "  newgrp docker"
