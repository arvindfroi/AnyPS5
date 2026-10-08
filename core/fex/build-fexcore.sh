#!/bin/bash
# Builds FEXCore for arm64 macOS into <directory>/build-macos: madeira's fork at its last MIT-licensed
# commit, with fex-macos.patch. Configure AnyPS5 with -DAPS5_FEXCORE_DIR=<directory> to build aps5-fex.
set -eu
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FEX="$(cd "$(dirname "${1:?usage: build-fexcore.sh <directory>}")" && pwd)/$(basename "$1")"
if [ ! -d "$FEX" ]; then
  git clone --filter=blob:none https://github.com/willfaust/FEX.git "$FEX"
  git -C "$FEX" checkout ac555dd81fa84f86d1927476e152451005e78f49
  git -C "$FEX" submodule update --init --depth 1 External/vixl External/fmt External/xxhash External/range-v3 \
      External/unordered_dense External/zydis External/tracy Source/Common/cpp-optparse
  git -C "$FEX" apply "$HERE/fex-macos.patch"
fi
cmake -S "$FEX" -B "$FEX/build-macos" -G "Unix Makefiles" -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_BUILD_TYPE=Release \
  -DTUNE_CPU=none -DCMAKE_DISABLE_FIND_PACKAGE_fmt=TRUE -DBUILD_TESTING=OFF -DBUILD_THUNKS=OFF -DBUILD_FEXCONFIG=OFF \
  -DBUILD_FEX_LINUX_TESTS=OFF -DENABLE_FEX_ALLOCATOR=OFF -DENABLE_ASSERTIONS=OFF -DENABLE_CCACHE=OFF -DENABLE_LTO=OFF
cmake --build "$FEX/build-macos" --target FEXCore FEXCore_Base JemallocLibs -j"$(sysctl -n hw.ncpu)"
