#!/bin/bash
# Install nmap if not already installed
if ! command -v nmap &> /dev/null
then
    echo "Installing nmap..."
    apt-get update && apt-get install -y nmap
fi

# Start the application
uvicorn app.main:app --host 0.0.0.0 --port $PORT
