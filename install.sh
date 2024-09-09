#!/bin/bash

# Step 1: Install dependencies
sudo apt update
sudo apt install -y nmap metasploit-framework exploitdb

# Step 2: Make the tool executable from any path
chmod +x reeekOn.py

# Step 3: Create a symlink to /usr/local/bin to make it globally accessible
sudo ln -s $(pwd)/reeekOn.py /usr/local/bin/reeekOn

# Step 4: Notify the user
echo "Tool installed successfully! You can run it using 'reeekOn' from any location."
