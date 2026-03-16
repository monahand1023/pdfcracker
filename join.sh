#!/bin/bash
#
# join.sh — Join a pdfcracker session from a remote Mac
#
# Copies the client binary from the server over SSH, then connects.
#
# Usage:
#   bash join.sh danm@192.168.50.170              # default port 9999
#   bash join.sh danm@192.168.50.170 8888         # custom port
#
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: bash join.sh user@server-ip [port]"
    echo ""
    echo "  Copies the pdfcracker client over SSH and starts cracking."
    exit 1
fi

SSH_TARGET="$1"
PORT="${2:-9999}"
SERVER_IP="${SSH_TARGET#*@}"
DIR="$HOME/.pdfcracker"

mkdir -p "$DIR"

# Only download if we don't have the client yet (or force with -f)
if [ ! -x "$DIR/client" ] || [ "${3:-}" = "-f" ]; then
    echo "Downloading client from $SSH_TARGET via SSH..."
    scp "$SSH_TARGET:Development/pdfcracker/client" "$SSH_TARGET:Development/pdfcracker/pdf_md5.metallib" "$DIR/"
    chmod +x "$DIR/client"
else
    echo "Using cached client in $DIR (pass -f to re-download)"
fi

echo "Starting pdfcracker client -> $SERVER_IP:$PORT"
echo "Press Ctrl+C to stop."
echo "---"
cd "$DIR"
exec ./client -s "$SERVER_IP" -p "$PORT"
