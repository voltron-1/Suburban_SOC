#!/usr/bin/env bash
# Suburban SOC Developer Onboarding (Linux/Mac/WSL)

echo -e "\e[36m=================================================\e[0m"
echo -e "\e[36m Suburban SOC - Developer Onboarding Script\e[0m"
echo -e "\e[36m=================================================\e[0m"
echo "Checking required dependencies for development..."
echo ""

missing_deps=0

# Git
if command -v git &> /dev/null; then
    echo -e "\e[32m[x] Git is installed\e[0m"
else
    echo -e "\e[31m[ ] Git is missing. Please install standard git tools.\e[0m"
    missing_deps=$((missing_deps+1))
fi

# gh CLI
if command -v gh &> /dev/null; then
    echo -e "\e[32m[x] GitHub CLI (gh) is installed\e[0m"
    if gh auth status &> /dev/null; then
        echo -e "\e[32m    -> Authenticated to GitHub\e[0m"
    else
        echo -e "\e[33m    -> Not authenticated. Run 'gh auth login'\e[0m"
    fi
else
    echo -e "\e[31m[ ] GitHub CLI (gh) is missing. Essential for Agile project management scripts in the root directory.\e[0m"
    missing_deps=$((missing_deps+1))
fi

# Docker
if command -v docker &> /dev/null; then
    echo -e "\e[32m[x] Docker is installed\e[0m"
    if docker info &> /dev/null; then
        echo -e "\e[32m    -> Docker engine is running\e[0m"
    else
        echo -e "\e[33m    -> Docker engine is not running\e[0m"
    fi
else
    echo -e "\e[31m[ ] Docker is missing. Required for Zeek analysis and local log streaming setup.\e[0m"
    missing_deps=$((missing_deps+1))
fi

# SSH
if command -v ssh &> /dev/null; then
    echo -e "\e[32m[x] SSH client is installed\e[0m"
else
    echo -e "\e[31m[ ] SSH client is missing. Required to connect to the router (10.18.81.1).\e[0m"
    missing_deps=$((missing_deps+1))
fi

echo ""
echo -e "\e[36m=================================================\e[0m"
if [ $missing_deps -gt 0 ]; then
    echo -e "\e[33mAction Required: Please install the missing dependencies to be fully configured for development.\e[0m"
else
    echo -e "\e[32mAll core dependencies are met! You are ready to develop.\e[0m"
fi
echo -e "\e[36m=================================================\e[0m"
