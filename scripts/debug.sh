#!/bin/sh

set -eu

if [ ! -f build/debug/meson-private/coredata.dat ]; then
  meson setup build/debug --buildtype=debug -Doptimization=0 -Ddebug=true \
    -Dstrip=false -Db_lto=false -Db_ndebug=false
else
  meson configure build/debug --buildtype=debug -Doptimization=0 -Ddebug=true \
    -Dstrip=false -Db_lto=false -Db_ndebug=false
fi

meson compile -C build/debug

gdb -batch -ex run -ex 'bt' --args build/debug/methuselah
