#!/bin/sh
# Orkardch installer for Termux (also works on ordinary Linux).
# It only (1) checks that Node.js is new enough and (2) installs the "orkardch" command.
# It never deletes anything and never edits your shell startup files.
set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"

if ! command -v node >/dev/null 2>&1; then
  echo "Node.js is not installed. In Termux run:  pkg install nodejs"
  exit 1
fi

MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
if [ "$MAJOR" -lt 18 ]; then
  echo "Node.js $(node -v) is too old. Orkardch needs version 18 or newer. In Termux run:  pkg upgrade nodejs"
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "Note: git is not installed. Orkardch works without it, but TunnelR's Git details and 'update' need it (pkg install git)."
fi

node "$DIR/orkardch.js" --install-launcher
echo
echo "Checking the installation (no network is used)..."
# Run the check with the launcher folder on PATH so it can see the command that was just installed.
PATH="${PREFIX:+$PREFIX/bin:}$HOME/.local/bin:$PATH" node "$DIR/orkardch.js" --doctor || true
echo
echo "Done. Start Orkardch by typing:  orkardch"
echo "To prove the network features work on this phone, run:  orkardch --doctor --online"
