#!/bin/sh

set -eu

meson_version=$(meson --version)
if ! printf '%s\n' "$meson_version" | awk -F. '{ exit !($1 > 1 || ($1 == 1 && $2 >= 5)) }'; then
  echo "ERROR: scripts/format.sh requires Meson 1.5 or newer." >&2
  exit 1
fi

find src -type f \( -name "*.cpp" -o -name "*.h" -o -name "*.hpp" -o -name "*.c" \) -exec clang-format -i {} \+

find include -type f \
  \( -name "*.cpp" -o -name "*.h" -o -name "*.hpp" -o -name "*.c" -o -name "*.cc" \) \
  ! -name "*_font.h" \
  -exec clang-format -i {} +

meson format -i meson.build
