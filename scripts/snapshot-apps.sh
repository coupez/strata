#!/bin/zsh
# Launches the built app on the Apps & Threats tab and saves window snapshots to build/snapshots.
set -euo pipefail
cd "$(dirname "$0")/.."
out="$PWD/build/snapshots"
rm -rf "$out" && mkdir -p "$out"
STRATA_TAB=apps STRATA_SNAPSHOT_DIR="$out" build/Strata.app/Contents/MacOS/Strata >/dev/null 2>&1 &
pid=$!
for _ in {1..240}; do
  [[ -f "$out/apps-02-ready.png" ]] && break
  sleep 1
done
sleep 1
kill $pid 2>/dev/null || true
ls "$out"
