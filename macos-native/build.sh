#!/bin/bash
# Builds FEXCore (madeira's MIT-era fork, commit ac555dd8) natively for macOS arm64 and the two proofs of concept.
set -eu
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FEX="$HERE/FEX"
if [ ! -d "$FEX" ]; then
  git clone --filter=blob:none https://github.com/willfaust/FEX.git "$FEX"
  git -C "$FEX" checkout ac555dd81fa84f86d1927476e152451005e78f49
  git -C "$FEX" submodule update --init --depth 1 External/vixl External/fmt External/xxhash External/range-v3 \
      External/unordered_dense External/zydis External/tracy Source/Common/cpp-optparse
  git -C "$FEX" apply "$HERE/fex-macos.patch"
fi
B="$FEX/build-macos"
cmake -S "$FEX" -B "$B" -G "Unix Makefiles" -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_BUILD_TYPE=Release -DTUNE_CPU=none \
  -DCMAKE_DISABLE_FIND_PACKAGE_fmt=TRUE -DBUILD_TESTING=OFF -DBUILD_THUNKS=OFF -DBUILD_FEXCONFIG=OFF \
  -DBUILD_FEX_LINUX_TESTS=OFF -DENABLE_FEX_ALLOCATOR=OFF -DENABLE_ASSERTIONS=OFF -DENABLE_CCACHE=OFF -DENABLE_LTO=OFF
cmake --build "$B" --target FEXCore FEXCore_Base JemallocLibs -j"$(sysctl -n hw.ncpu)"
INC=(-I"$FEX/FEXCore/include" -I"$B/include" -I"$FEX/External/fmt/include" -I"$FEX/FEXHeaderUtils" \
     -I"$FEX/External/range-v3/include" -I"$FEX/External/unordered_dense/include")
LIBS=("$B/FEXCore/Source/libFEXCore.a" "$B/FEXCore/Source/libFEXCore_Base.a" "$B/FEXCore/Source/libJemallocLibs.a" \
      "$B/External/fmt/libfmt.a" "$B/External/xxhash/cmake_unofficial/libxxhash.a" \
      "$B/External/cephes/libcephes_128bit.a" "$B/External/SoftFloat-3e/libsoftfloat_3e.a")
for poc in poc_arith poc_native_call; do
  clang++ -std=c++20 -O1 "${INC[@]}" "$HERE/$poc.cpp" "${LIBS[@]}" -o "$HERE/$poc"
  "$HERE/$poc"
done
