#!/bin/sh
# Safe update: fast-forward only, and only when this folder is a Git clone with no local changes.
# It never discards your work. Your settings and investigations live outside this folder and are untouched.
set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

if [ ! -d .git ]; then
  echo "This folder is not a Git clone, so there is nothing to pull."
  echo "To update from a new ZIP: extract it to a NEW folder, then run install-termux.sh there."
  exit 1
fi
if ! command -v git >/dev/null 2>&1; then
  echo "git is not installed. In Termux run:  pkg install git"
  exit 1
fi
if [ -n "$(git status --porcelain)" ]; then
  echo "You have local changes in $DIR, so I will not update automatically."
  echo "Save or commit them first, then run this again."
  exit 1
fi

git pull --ff-only
node orkardch.js --doctor || true
echo "Updated. If you moved this folder, re-run:  node orkardch.js --install-launcher"
