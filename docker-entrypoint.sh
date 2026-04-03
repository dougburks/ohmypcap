#!/bin/sh
set -e

# Create data directory if it doesn't exist
mkdir -p "$DATA_DIR"

# Run the application
exec python3 /app/ohmypcap.py
