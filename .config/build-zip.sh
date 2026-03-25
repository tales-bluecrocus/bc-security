#!/bin/bash

# Local build of the plugin for manual upload to WordPress
# Usage: ./.config/build-zip.sh

set -e

# Get plugin root directory (parent of .config)
PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$PLUGIN_DIR/dist-release"
OUTPUT="$PLUGIN_DIR/../bc-security.zip"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Building BC Security plugin...${NC}\n"

# Clean old artifacts
echo -e "${GREEN}Cleaning old build...${NC}"
rm -rf "$BUILD_DIR"
rm -f "$OUTPUT"

# Install composer production deps
echo -e "${GREEN}Installing composer dependencies...${NC}"
cd "$PLUGIN_DIR"
composer install --no-dev --optimize-autoloader --quiet

# Assemble distribution
echo -e "${GREEN}Packaging plugin...${NC}"
mkdir -p "$BUILD_DIR"

rsync -a "$PLUGIN_DIR/" "$BUILD_DIR/bc-security/" \
  --exclude='.git/' \
  --exclude='.github/' \
  --exclude='.vscode/' \
  --exclude='.config/' \
  --exclude='.claude/' \
  --exclude='dist-release/' \
  --exclude='.gitignore' \
  --exclude='.gitattributes' \
  --exclude='composer.json' \
  --exclude='composer.lock' \
  --exclude='docs/' \
  --exclude='CLAUDE.md' \
  --exclude='README.md' \
  --exclude='*.log'

# Create ZIP
cd "$BUILD_DIR"
zip -rq "$OUTPUT" bc-security/

# Cleanup temp dir
rm -rf "$BUILD_DIR"

# Show result
SIZE=$(du -h "$OUTPUT" | cut -f1)
echo ""
echo -e "${GREEN}Done: $OUTPUT ($SIZE)${NC}"
echo ""

# Show what's in the zip for verification
echo -e "${BLUE}Contents:${NC}"
zipinfo -1 "$OUTPUT" | head -30
TOTAL=$(zipinfo -1 "$OUTPUT" | wc -l)
if [ "$TOTAL" -gt 30 ]; then
    echo "... and $((TOTAL - 30)) more files"
fi
echo ""
