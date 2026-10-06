#!/usr/bin/env bash
set -euo pipefail

ABI="arm64-v8a"
API="24"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -Abi|--abi)
      ABI="$2"
      shift 2
      ;;
    -Api|--api)
      API="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

case "$ABI" in
  arm64-v8a)
    TARGET_TRIPLE="aarch64-linux-android"
    CLANG_PREFIX="aarch64-linux-android"
    INCLUDE_ARCH="aarch64-linux-android"
    ;;
  armeabi-v7a)
    TARGET_TRIPLE="armv7-linux-androideabi"
    CLANG_PREFIX="armv7a-linux-androideabi"
    INCLUDE_ARCH="arm-linux-androideabi"
    ;;
  x86_64)
    TARGET_TRIPLE="x86_64-linux-android"
    CLANG_PREFIX="x86_64-linux-android"
    INCLUDE_ARCH="x86_64-linux-android"
    ;;
  *)
    echo "Unsupported ABI: $ABI" >&2
    exit 2
    ;;
esac

if ! rustup target list --installed | grep -qx "$TARGET_TRIPLE"; then
  echo "Error: Rust target $TARGET_TRIPLE is not installed." >&2
  echo "Please run: rustup target add $TARGET_TRIPLE" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CRATE="$SCRIPT_DIR/aether"
TARGET="$CRATE/target-android"

SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [[ -z "$SDK" ]]; then
  SDK="$HOME/Android/Sdk"
fi

NDK_VERSION="26.3.11579264"
NDK="$SDK/ndk/$NDK_VERSION"
if [[ ! -d "$NDK" ]]; then
  NDK="$(find "$SDK/ndk" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -n 1 || true)"
fi

HOST_TAG="linux-x86_64"
BIN="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin"
SYSROOT="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/sysroot"
CMAKE="$SDK/cmake/3.22.1/bin/cmake"
if [[ ! -x "$CMAKE" ]]; then
  CMAKE="$(command -v cmake || true)"
fi

if [[ -z "$NDK" || ! -d "$NDK" || ! -d "$BIN" || -z "$CMAKE" || ! -x "$CMAKE" ]]; then
  echo "Android build requirements missing (NDK or CMake). SDK path: $SDK" >&2
  exit 1
fi

# Force fresh dependency resolution for rand 0.10 (avoid stale Cargo.lock from cache)
rm -f "$CRATE/Cargo.lock"
(
  cd "$CRATE"
  cargo generate-lockfile
)

export ANDROID_NDK_HOME="$NDK"
export ANDROID_NDK_ROOT="$NDK"
export CMAKE="$CMAKE"
export CMAKE_GENERATOR="Ninja"
export CARGO_TARGET_DIR="$TARGET"
export PATH="$(dirname "$CMAKE"):$PATH"
# bindgen needs libclang's C API; the NDK's libclang-cpp shim does not export it.
if [[ -z "${LIBCLANG_PATH:-}" ]]; then
  if compgen -G "/usr/lib/libclang.so*" >/dev/null; then
    export LIBCLANG_PATH="/usr/lib"
  else
    export LIBCLANG_PATH="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/musl/lib"
  fi
fi

# boring-sys builds BoringSSL itself. boring 5.2 reworked the build: the
# second-target CMake re-configure that 4.22 hit no longer wipes the cache
# (build_boringssl_or_get_prebuilt compiles `ssl` then `crypto` from one
# config), so the manual bootstrap pass that used to exist here was finding
# a libssl.a whose header layout the new version does not produce. Build
# once and let boring-sys own the whole tree.
#
# BORING_BSSL_ASSUME_PATCHED is dropped too: in 5.2 it is only valid together
# with BORING_BSSL_PATH/SOURCE_PATH (config.rs errors otherwise), and this
# crate uses none of the rpk / relax-cert-validation / underscore-wildcards
# features those patches carry.
export CLANG_PATH="$BIN/clang"

RUST_ENV_SUFFIX="${TARGET_TRIPLE^^}"
RUST_ENV_SUFFIX="${RUST_ENV_SUFFIX//-/_}"
RUST_TARGET_SUFFIX="${TARGET_TRIPLE//-/_}"

# boring-sys 5.2 links libc++ dynamically by default, which makes libaether.so
# NEEDED libc++_shared.so. The APK does not ship it (the other engines are C),
# so dlopen fails and the app will not even start. Statically link and bundle
# libc++ instead — the fix CluvexStudio shipped in aether 6cf29b3.
# Scope: keep it only on this target (upstream used _<target> not plain).
export "BORING_BSSL_RUST_CPPLIB_${RUST_TARGET_SUFFIX}=static:-bundle=c++"

export "CARGO_TARGET_${RUST_ENV_SUFFIX}_LINKER=$BIN/${CLANG_PREFIX}${API}-clang"
export "CARGO_TARGET_${RUST_ENV_SUFFIX}_AR=$BIN/llvm-ar"
export "AR_${RUST_TARGET_SUFFIX}=$BIN/llvm-ar"
export "CC_${RUST_TARGET_SUFFIX}=$BIN/clang"
export "CXX_${RUST_TARGET_SUFFIX}=$BIN/clang++"
export "CFLAGS_${RUST_TARGET_SUFFIX}=--target=${CLANG_PREFIX}${API}"
export "CXXFLAGS_${RUST_TARGET_SUFFIX}=--target=${CLANG_PREFIX}${API}"
export "BINDGEN_EXTRA_CLANG_ARGS_${RUST_TARGET_SUFFIX}=--target=${CLANG_PREFIX}${API} --sysroot=$SYSROOT -I$SYSROOT/usr/include -I$SYSROOT/usr/include/$INCLUDE_ARCH"
export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-Wl,-soname,libaether.so -C link-arg=-Wl,-z,max-page-size=16384"
# No -z common-page-size here on purpose: with common-page-size=16384 lld pads
# PT_GNU_RELRO out to a 16K boundary that can overhang the end of the LOAD
# segment holding it (RELRO@4K OVERRUN on every .so since the MIM port grew
# the Rust core). 16K device support comes from max-page-size alone; the
# loader honors max-page-size for mapping and common-page-size only shrinks
# the RELRO padding, so dropping it fixes the overhang with no 16K cost.

cd "$CRATE"
cargo build --release --lib --target "$TARGET_TRIPLE"

LIBRARY="$TARGET/$TARGET_TRIPLE/release/libaether.so"
for DESTINATION in "$ROOT/core/android-libs/$ABI" "$ROOT/app/src/main/jniLibs/$ABI"; do
  mkdir -p "$DESTINATION"
  cp -f "$LIBRARY" "$DESTINATION/libaether.so"
done
