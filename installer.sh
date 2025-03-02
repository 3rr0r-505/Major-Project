#!/bin/bash

# Installation script for honeypott3r

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root (use sudo)."
    exit 1
fi

echo "[*] Installing HoneyPott3r..."

# Set the installation directory
INSTALL_DIR="/opt/honeypott3r"

# Create the installation directory
mkdir -p "$INSTALL_DIR"

# Copy all files to the installation directory
cp -r ./* "$INSTALL_DIR"

# Ensure necessary scripts are executable
chmod +x "$INSTALL_DIR/src/main.py"
chmod +x "$INSTALL_DIR/uninstall.sh"

# Set correct ownership
chown -R $(whoami):$(whoami) "$INSTALL_DIR"

# Create a wrapper script to start MongoDB before launching honeypott3r
WRAPPER_SCRIPT="$INSTALL_DIR/honeypott3r.sh"

cat <<EOL > "$WRAPPER_SCRIPT"
#!/bin/bash

# Start MongoDB if it's not already running
if ! pgrep -x "mongod" > /dev/null; then
    echo "[*] Starting MongoDB..."
    systemctl start mongod
else
    echo "[*] MongoDB is already running."
fi

# Run the honeypott3r tool
exec python3 "$INSTALL_DIR/src/main.py" "\$@"
EOL

# Make the wrapper script executable
chmod +x "$WRAPPER_SCRIPT"

# Create a symlink in /usr/local/bin to make it globally accessible
ln -sf "$WRAPPER_SCRIPT" /usr/local/bin/honeypott3r

# Install Python dependencies
install_pypkg(){
    REQ_FILE="$INSTALL_DIR/requirements.txt"
    PACKAGES=()

    # Check if the file exists
    if [ ! -f "$REQ_FILE" ]; then
        echo "Error: $REQ_FILE not found!"
        exit 1
    fi

    # Read the file and store package names in an array
    while IFS= read -r package || [[ -n "$package" ]]; do
        PACKAGES+=("$package")
    done < "$REQ_FILE"

    echo -e "[+] Packages to install: ${PACKAGES[*]}\n"

    # Ensure pip is installed
    if ! command -v pip &> /dev/null; then
        echo "[!] pip not found. Installing..."
        sudo apt update && sudo apt install -y python3-pip &> /dev/null
    fi

    # Loop through each package and install
    for package in "${PACKAGES[@]}"; do
        echo "[*] Installing $package using pip..."
        
        # Try installing with pip
        if python3 -m pip install "$package" >/dev/null 2>&1; then
            echo "[>] $package successfully installed via pip."
        else
            echo "[!] pip install failed, trying apt install..."
            
            APT_CMD="sudo apt install -y python3-$package"
            echo "[*] Executing: $APT_CMD"
            
            if $APT_CMD >/dev/null 2>&1; then
                echo "[+] $package successfully installed via apt."
            else
                echo "[!] Failed to install $package."
            fi
        fi

        # **Recheck if the package is installed**
        echo "[*] Verifying installation of $package..."
        if python3 -c "import $package" >/dev/null 2>&1; then
            echo -e "[+] $package is successfully installed and working.\n"
        else
            echo -e "[Error] $package is still not installed!\n"
        fi
    done
}

# Check for required tools
chk_tools(){
    echo "[*] Checking required tools..."
    INSTALLED_TOOLS=()
    MISSING_TOOLS=()

    for tool in netcat trivy bandit wpscan nmap nikto msfconsole mongod docker; do
        if command -v "$tool" &> /dev/null; then
            INSTALLED_TOOLS+=("$tool")
        else
            MISSING_TOOLS+=("$tool")
        fi
    done

    # Special check for safety-cli (can be installed via pipx or apt)
    if ! [ -x "$(command -v safety)" ]; then
    	INSTALLED_TOOLS+=("safety")
    else
	MISSING_TOOLS+=("safety")
    fi

    # Print installed tools
    if [ ${#INSTALLED_TOOLS[@]} -ne 0 ]; then
        echo -e "\n[+] The following tools are installed:"
        for tool in "${INSTALLED_TOOLS[@]}"; do
            echo "[>] $tool installed"
        done
    fi

    # Print missing tools
    if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
        echo -e "\n[!] Warning: The following tools are not installed:"
        for tool in "${MISSING_TOOLS[@]}"; do
            echo "[>] $tool missing"
        done
        # Provide installation guide link
        echo -e "\n[*] For tool installation guide, check: https://github.com/3rr0r-505/HoneyPott3r/wiki/Dependencies-&-Tools"
    fi
}

install_pypkg
chk_tools

echo "[*] HoneyPott3r has been installed successfully!"
echo "[*] You can now run the tool using the command: sudo honeypott3r"
