#!/bin/bash

# Create a new plugin version/release
# Usage: ./.config/create-release.sh 2.0.1

set -e

# Get plugin root directory (parent of .config)
PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PLUGIN_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Validate version argument
if [ -z "$1" ]; then
    echo -e "${RED}Error: You must provide a version number${NC}"
    echo -e "Usage: ./.config/create-release.sh 2.0.1"
    exit 1
fi

VERSION=$1
TAG="v$VERSION"

# Validate semantic versioning format (X.Y.Z)
if ! [[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo -e "${RED}Error: Invalid version. Use format: X.Y.Z (e.g., 2.0.1)${NC}"
    exit 1
fi

echo -e "${BLUE}Creating release $TAG...${NC}\n"

# Check for uncommitted changes
if ! git diff-index --quiet HEAD --; then
    echo -e "${RED}Error: There are uncommitted changes.${NC}"
    echo -e "Commit or stash before continuing.\n"
    git status --short
    exit 1
fi

# Check if we're on main branch
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "main" ]; then
    echo -e "${YELLOW}Warning: You are on branch '$CURRENT_BRANCH', not 'main'${NC}"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check if tag already exists
if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo -e "${RED}Error: Tag $TAG already exists!${NC}"
    echo -e "Use: git tag -d $TAG (local) and git push --delete origin $TAG (remote)"
    exit 1
fi

# Get current version from bc-security.php
CURRENT_VERSION=$(grep -m 1 "Version:" bc-security.php | sed 's/.*Version: *//' | tr -d '\r')
echo -e "${BLUE}Current version: $CURRENT_VERSION${NC}"
echo -e "${BLUE}New version: $VERSION${NC}\n"

# Confirm before proceeding
read -p "Confirm release $TAG? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Operation cancelled.${NC}"
    exit 1
fi

# Update version in bc-security.php (header + constant)
echo -e "${GREEN}Updating version in bc-security.php...${NC}"
if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' "s/Version: .*/Version:     $VERSION/" bc-security.php
    sed -i '' "s/define( 'BC_SECURITY_VERSION', '.*' )/define( 'BC_SECURITY_VERSION', '$VERSION' )/" bc-security.php
else
    sed -i "s/Version: .*/Version:     $VERSION/" bc-security.php
    sed -i "s/define( 'BC_SECURITY_VERSION', '.*' )/define( 'BC_SECURITY_VERSION', '$VERSION' )/" bc-security.php
fi

# Verify the change
NEW_VERSION=$(grep -m 1 "Version:" bc-security.php | sed 's/.*Version: *//' | tr -d '\r')
if [ "$NEW_VERSION" != "$VERSION" ]; then
    echo -e "${RED}Error: Failed to update version in bc-security.php${NC}"
    exit 1
fi

echo -e "${GREEN}Version updated: $CURRENT_VERSION -> $VERSION${NC}\n"

# Commit version bump
echo -e "${GREEN}Committing version change...${NC}"
git add bc-security.php
if git diff --staged --quiet; then
    echo -e "${YELLOW}No version change (already at $VERSION)${NC}\n"
else
    git commit -m "chore: bump version to $VERSION"
fi

# Create annotated tag
echo -e "${GREEN}Creating tag $TAG...${NC}"
git tag -a "$TAG" -m "Release $VERSION"

# Push changes
echo -e "${GREEN}Pushing to GitHub...${NC}"
git push origin "$CURRENT_BRANCH"
git push origin "$TAG"

echo ""
echo -e "${GREEN}Release $TAG created successfully!${NC}"
echo ""
echo -e "${BLUE}Monitor the build at:${NC}"
echo -e "   https://github.com/tales-bluecrocus/bc-security/actions"
echo ""
echo -e "${BLUE}After the build completes (~1-2 min), the release will be available at:${NC}"
echo -e "   https://github.com/tales-bluecrocus/bc-security/releases/tag/$TAG"
echo ""
echo -e "${YELLOW}WordPress will detect the update automatically within 12 hours.${NC}"
echo -e "${YELLOW}Or force a check at: Plugins > Installed Plugins${NC}"
echo ""
