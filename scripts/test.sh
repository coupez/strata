#!/bin/zsh
# Generates the project and runs the unit tests. Pass a suite name to run only that suite:
#   scripts/test.sh LaunchItemsTests
set -euo pipefail
cd "$(dirname "$0")/.."
xcodegen generate --quiet
only=()
[[ $# -gt 0 ]] && only=(-only-testing:StrataTests/$1)
xcodebuild -project Strata.xcodeproj -scheme Strata -derivedDataPath build/DerivedData \
  -destination 'platform=macOS,arch=arm64' test "${only[@]}" 2>&1 \
  | grep -E "✔|✘|error:|Expectation failed|TEST (SUCCEEDED|FAILED)|Test run"
