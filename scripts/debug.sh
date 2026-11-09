#!/bin/sh

set -eu

OPT_PREFIX=$HOME/opt
X11_PREFIX=${OPT_PREFIX}/x11/current
X11_PKGCONFIG="${X11_PREFIX}/lib/pkgconfig:${X11_PREFIX}/share/pkgconfig"
LOCAL_PKGCONFIG=${HOME}/.local/lib/pkgconfig

if [ -n "${PKG_CONFIG_PATH+set}" ]; then
  export PKG_CONFIG_PATH="${X11_PKGCONFIG}:${LOCAL_PKGCONFIG}:${PKG_CONFIG_PATH}"
else
  export PKG_CONFIG_PATH="${X11_PKGCONFIG}:${LOCAL_PKGCONFIG}"
fi

export BOOST_ROOT=${OPT_PREFIX}/boost/current

if [ -n "${CMAKE_PREFIX_PATH+set}" ]; then
  export CMAKE_PREFIX_PATH="${X11_PREFIX}:${OPT_PREFIX}/boost/current:${CMAKE_PREFIX_PATH}"
else
  export CMAKE_PREFIX_PATH="${X11_PREFIX}:${OPT_PREFIX}/boost/current"
fi

if [ ! -f .build/debug/build.ninja ]; then
  rm -rf .build/debug
  meson setup .build/debug --buildtype=debug -Doptimization=0 -Ddebug=true \
    -Dstrip=false -Db_lto=false -Db_ndebug=false
else
  meson configure .build/debug --buildtype=debug -Doptimization=0 -Ddebug=true \
    -Dstrip=false -Db_lto=false -Db_ndebug=false
fi

meson compile -C .build/debug

gdb -batch -ex run -ex 'bt' --args .build/debug/methuselah
