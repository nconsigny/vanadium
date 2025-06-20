#!/bin/bash

set -e

# Downloads the latest Vanadium binaries from GitHub and unzips them into the target folder,
# in the same location as if they were built from source.

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if 'target' folder exists in the script's directory
if [ -d "$SCRIPT_DIR/target" ]; then
  echo "Error: 'target' folder already exists in $SCRIPT_DIR"
  exit 1
fi

# Download the zip file to the script's directory
curl -L -o "$SCRIPT_DIR/__vanadium_binaries_temp.zip" https://github.com/LedgerHQ/vanadium/releases/download/latest/vanadium_binaries.zip

# Create target folder and unzip contents in the script's directory
mkdir "$SCRIPT_DIR/target"
unzip "$SCRIPT_DIR/__vanadium_binaries_temp.zip" -d "$SCRIPT_DIR/target"

# Delete the zip file
rm "$SCRIPT_DIR/__vanadium_binaries_temp.zip"
