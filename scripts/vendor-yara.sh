#!/bin/zsh
# Downloads a pinned libyara release and copies just what Strata compiles into Vendor/yara.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=4.5.8
SHA256=c322414975ff6f701149856613afdcd92a7e6939c284c798ae3c85618197efaa
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -sSfL -o "$work/yara.tgz" "https://github.com/VirusTotal/yara/archive/refs/tags/v$VERSION.tar.gz"
echo "$SHA256  $work/yara.tgz" | shasum -a 256 -c --quiet
tar xzf "$work/yara.tgz" -C "$work"
src="$work/yara-$VERSION/libyara"
dst=Vendor/yara/libyara
rm -rf $dst
mkdir -p $dst/modules $dst/proc
cp "$src"/*.c "$src"/*.h $dst/
cp -R "$src/include" "$src/tlshc" $dst/
cp "$src/proc/none.c" $dst/proc/
cp "$src/modules/module_list" $dst/modules/
for module in tests elf math time console string hash; do cp -R "$src/modules/$module" $dst/modules/; done
mkdir -p $dst/modules/pe && cp "$src/modules/pe/pe.c" "$src/modules/pe/pe_utils.c" $dst/modules/pe/
cp "$work/yara-$VERSION/COPYING" Vendor/yara/COPYING
echo "$VERSION" > Vendor/yara/VERSION
echo "Vendored libyara $VERSION into Vendor/yara"
