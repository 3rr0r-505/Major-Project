#!/bin/bash

# Installation script for honeypott3r
# add the shebang (#!/usr/bin/env python3) to the main script (main.py) since it is the entry point. Other module files don't need it.

echo "Installing HoneyPott3r..."

# Set the installation directory
INSTALL_DIR="/opt/honeypott3r"

# Create the installation directory
sudo mkdir -p $INSTALL_DIR

# Copy all files to the installation directory
sudo cp -r ./* $INSTALL_DIR

# Ensure the main script is executable
sudo chmod +x $INSTALL_DIR/main.py

# Create a symlink in /usr/local/bin to make it globally accessible
sudo ln -sf $INSTALL_DIR/main.py /usr/local/bin/honeypott3r

# Install Python dependencies
if [ -f "$INSTALL_DIR/requirements.txt" ]; then
    echo "Installing Python dependencies..."
    pip install -r $INSTALL_DIR/requirements.txt
fi

echo "HoneyPott3r has been installed successfully!"
echo "You can now run the tool using the command: HoneyPott3r"
