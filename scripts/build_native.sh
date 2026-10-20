#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

command -v cc >/dev/null 2>&1 || {
  echo "ERROR: a C compiler is required to build the native Threefish library." >&2
  exit 1
}

rm -f native/libthreefish_native.so
cc -std=c11 -O2 -fPIC -shared \
  native/threefish1024.c \
  -o native/libthreefish_native.so

echo "Native Threefish library built for CI."
