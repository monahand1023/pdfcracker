#!/bin/bash
#
# deploy.sh — Deploy pdfcracker client to a remote Apple Silicon Mac
#
# Run from the server machine. Handles everything over SSH:
#   1. Copies client binary + Metal shader to the remote Mac
#   2. Launches the client, pointing back at this machine's server
#
# Usage:
#   ./deploy.sh user@host                    # auto-detect server IP, default port
#   ./deploy.sh user@host 8888               # custom port
#   ./deploy.sh user@host 9999 192.168.1.5   # explicit server IP
#
# Multiple machines:
#   ./deploy.sh dan@mac-mini.local &
#   ./deploy.sh dan@macbook.local &
#   wait
#
# Press Ctrl+C to stop the remote client.

set -euo pipefail

usage() {
    echo "Usage: $0 <user@host> [port] [server-ip]"
    echo ""
    echo "  user@host   SSH destination for the remote Mac"
    echo "  port        Server port (default: 9999)"
    echo "  server-ip   Server IP (default: auto-detect)"
    echo ""
    echo "Examples:"
    echo "  $0 dan@192.168.1.20              # deploy and start"
    echo "  $0 dan@mac-mini.local 8888       # custom port"
    echo "  $0 dan@mac-mini.local 9999 192.168.1.5  # explicit server IP"
    exit 1
}

if [ $# -lt 1 ]; then
    usage
fi

REMOTE="$1"
PORT="${2:-9999}"
SERVER_IP="${3:-}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REMOTE_DIR="\$HOME/.pdfcracker"

# Auto-detect server IP if not specified
if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(ipconfig getifaddr en0 2>/dev/null || true)
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP=$(ipconfig getifaddr en1 2>/dev/null || true)
    fi
    if [ -z "$SERVER_IP" ]; then
        # Try all interfaces
        SERVER_IP=$(ifconfig | grep 'inet ' | grep -v '127.0.0.1' | head -1 | awk '{print $2}' || true)
    fi
    if [ -z "$SERVER_IP" ]; then
        echo "Error: Could not auto-detect server IP. Specify it as the third argument."
        exit 1
    fi
    echo "Server IP: $SERVER_IP"
fi

# Build if needed
if [ ! -f "$SCRIPT_DIR/client" ] || [ ! -f "$SCRIPT_DIR/pdf_md5.metallib" ]; then
    echo "Building client..."
    make -C "$SCRIPT_DIR" client
fi

echo "Deploying to $REMOTE..."

# Copy files in one shot (tar over ssh is faster than multiple scp calls)
tar cf - -C "$SCRIPT_DIR" client pdf_md5.metallib | \
    ssh "$REMOTE" 'mkdir -p ~/.pdfcracker && tar xf - -C ~/.pdfcracker && chmod +x ~/.pdfcracker/client'

echo "Starting client on $REMOTE -> $SERVER_IP:$PORT"
echo "Press Ctrl+C to stop."
echo "---"

# Run client on remote machine (interactive, so Ctrl+C propagates gracefully)
ssh -t "$REMOTE" "cd ~/.pdfcracker && ./client -s $SERVER_IP -p $PORT"
