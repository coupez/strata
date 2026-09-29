#!/bin/zsh
# Generates the Xcode project, builds a Release app, and copies it to ./build/Strata.app
set -euo pipefail
cd "$(dirname "$0")/.."
xcodegen generate --quiet
xcodebuild -project Strata.xcodeproj -scheme Strata -configuration "${CONFIG:-Release}" -derivedDataPath build/DerivedData build -quiet
rm -rf build/Strata.app
cp -R "build/DerivedData/Build/Products/${CONFIG:-Release}/Strata.app" build/Strata.app
echo "Built build/Strata.app"
