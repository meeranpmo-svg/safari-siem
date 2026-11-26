#!/bin/bash
# Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
# update-safari.sh - update the Safari platform on this server in one step: pull the latest code, then upgrade in place.
#
#   bash deploy/update-safari.sh            (run from the safari-siem checkout; do NOT use sudo - it asks for the password itself)
#
# It fetches the latest commit on the current branch (fast-forward only, so a tampered or diverged history is refused), then runs
# the re-runnable installer, which upgrades every part in place and KEEPS all settings, secrets and data (no --auth-src on a
# re-run: the sign-in service and its 2FA are left exactly as they are). Afterwards, refresh the browser with Ctrl+F5.
set -euo pipefail
say() { echo "==> $*"; }; die() { echo "!! $*" >&2; exit 1; }

# the repository root (this script lives in deploy/)
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"
[ -f "$HERE/deploy/install-fresh-server.sh" ] || die "$HERE is not the Safari platform checkout (deploy/install-fresh-server.sh is missing)"
command -v git >/dev/null 2>&1 || die "git is not installed"
git -C "$HERE" rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "$HERE is not a git checkout - clone the repository first"

# run git as the person who owns the checkout, never as root (root in someone else's checkout is refused by git, and would leave
# root-owned files behind). If this script was started with sudo, step back down to that owner for the pull.
OWNER="$(stat -c '%U' "$HERE")"
gitpull() {
  if [ "$(id -u)" = 0 ] && [ "$OWNER" != root ]; then sudo -u "$OWNER" git -C "$HERE" "$@"; else git -C "$HERE" "$@"; fi
}

# refuse to throw away local edits (a hand change to a tracked file); say what they are
if ! gitpull diff --quiet || ! gitpull diff --cached --quiet; then
  echo "!! this checkout has local changes - they would block the update. Review them with:  git -C $HERE status" >&2
  gitpull status --short >&2 || true
  die "commit or stash your local changes, then run this again"
fi

BR="$(gitpull rev-parse --abbrev-ref HEAD)"; [ "$BR" = HEAD ] && die "the checkout is on a detached commit, not a branch - 'git checkout main' first"
OLD="$(gitpull rev-parse --short HEAD)"
say "updating the code on branch '$BR' (current $OLD)"
# the network can hiccup; try a few times with a short backoff
n=0; until gitpull fetch --prune origin; do n=$((n + 1)); [ "$n" -ge 4 ] && die "could not reach the git remote after several tries - check the network and run again"; sleep $((n * 3)); done
gitpull merge --ff-only "origin/$BR" || die "the local branch and origin/$BR have diverged (a fast-forward is not possible) - a person must reconcile them (git -C $HERE status); nothing was installed"
NEW="$(gitpull rev-parse --short HEAD)"
if [ "$OLD" = "$NEW" ]; then say "already up to date ($NEW) - re-running the installer anyway so any half-done step finishes"; else say "updated $OLD -> $NEW"; fi

# upgrade in place (needs root; the installer keeps settings, secrets and data). Pass through any extra arguments (e.g. --host).
say "installing / upgrading the platform - this keeps all settings, secrets and data"
if [ "$(id -u)" = 0 ]; then bash "$HERE/deploy/install-fresh-server.sh" "$@"; else sudo bash "$HERE/deploy/install-fresh-server.sh" "$@"; fi

say "update finished - open the platform and refresh with Ctrl+F5"
