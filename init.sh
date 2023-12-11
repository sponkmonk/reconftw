#!/usr/bin/env bash

# This script initializes reconftw by cloning the repository and setting up the environment.

# Oneliner for set up and installation:
# curl -sSL https://raw.githubusercontent.com/six2dez/reconftw/v3.0-dev/init.sh | bash

set -e # Exit on error
set -u # Exit on uninitialized variable

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo -e "${GREEN}Setting up reconftw...${NC}"

# Check if git is installed
if ! command -v git &>/dev/null; then
    echo -e "${RED}Error: git is not installed. Please install git and try again.${NC}"
    exit 1
fi

# Ensure the directory exists before cloning
mkdir -p "${HOME}/.reconftw"

echo -e "${GREEN}Cloning reconftw...${NC}"

if [[ ! -d "${HOME}/.reconftw/reconftw" ]]; then
    git clone --branch v3.0-dev https://github.com/six2dez/reconftw.git "${HOME}/.reconftw"
    echo -e "${GREEN}reconftw cloned successfully.${NC}"
else
    echo "reconftw already cloned. Pulling latest changes..."
    git -C "${HOME}/.reconftw" pull
fi

echo -e "${GREEN}Setting up the environment vars...${NC}"

chmod +x "${HOME}"/.reconftw/bin/*

# Check if reconftw.cfg exists before sourcing
if [[ -f "${HOME}/.reconftw/reconftw.cfg" ]]; then
    source "${HOME}"/.reconftw/reconftw.cfg
else
    echo -e "${RED}Error: reconftw.cfg not found. Please ensure it exists in the specified directory.${NC}"
    exit 1
fi

echo -e "${GREEN}The installer will now install the required tools. Are you sure?${NC}"

while true; do
    read -p "Continue (y/n) [default: y]? " choice
    choice=${choice:-y}
    case ${choice} in
    [Yy]*)
        "${HOME}"/.reconftw/install.sh
        break
        ;;
    [Nn]*) exit ;;
    *) echo "Please answer y or n." ;;
    esac
done
