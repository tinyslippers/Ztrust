#!/bin/bash
# Update package lists
echo "Updating package lists…"
sudo apt-get update
# Upgrade installed packages
echo "Upgrading installed packages…"
sudo apt-get upgrade -y
# Perform distribution upgrade (if available)
echo "Performing distribution upgrade (if available)…"
sudo apt-get dist-upgrade -y
# Remove unused packages
echo "Removing unused packages…"
sudo apt-get autoremove -y
# Clean up package cache
echo "Cleaning up package cache…"
sudo apt-get autoclean
echo "Kali Linux system is now fully updated."
