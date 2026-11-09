#!/bin/sh
set -eu

OPT_PREFIX=$HOME/opt
X11_PREFIX=${OPT_PREFIX}/x11/current

if [ ! -d "${OPT_PREFIX}" ]; then
  echo "ERROR: $HOME/opt directory is missing!"
  exit 1
else
  echo "${OPT_PREFIX} directory: OK"
fi

if [ ! -e "${X11_PREFIX}/lib/libX11.so" ] && [ ! -e "${X11_PREFIX}/lib/libX11.a" ]; then
  echo "x11: missing!!! run scripts/deps-x11.sh"
fi

LOCAL_PKGCONFIG=${HOME}/.local/lib/pkgconfig
if [ ! -d "${LOCAL_PKGCONFIG}" ]; then
  mkdir -p ${LOCAL_PKGCONFIG}
fi

LOCAL_BIN=${HOME}/.local/bin
if [ ! -d "${LOCAL_BIN}" ]; then
  mkdir -p ${LOCAL_BIN}
fi

X11_PKGCONFIG="${X11_PREFIX}/lib/pkgconfig:${X11_PREFIX}/share/pkgconfig"

if [ -n "${PKG_CONFIG_PATH+set}" ]; then
  export PKG_CONFIG_PATH="${X11_PKGCONFIG}:${LOCAL_PKGCONFIG}:${PKG_CONFIG_PATH}"
else
  export PKG_CONFIG_PATH="${X11_PKGCONFIG}:${LOCAL_PKGCONFIG}"
fi
if [ ! -f "${OPT_PREFIX}/boost/current/lib/libboost_atomic.so" ]; then
  echo "boost: missing!!!"
fi
BOOST_VERSION=v1.91.0
BOOST_STRING=boost-1.91.0-1
export BOOST_ROOT=${OPT_PREFIX}/boost/current

if [ -n "${CMAKE_PREFIX_PATH+set}" ]; then
  CMAKE_PREFIX_PATH="${X11_PREFIX}:${OPT_PREFIX}/boost/current:${CMAKE_PREFIX_PATH}"
else
  CMAKE_PREFIX_PATH="${X11_PREFIX}:${OPT_PREFIX}/boost/current"
fi
export CMAKE_PREFIX_PATH

if [ ! -f ".build/build.ninja" ]; then
  rm -rf .build
  meson setup .build --buildtype=release --prefer-static --default-library=static
fi

export BOOST_ROOT=${OPT_PREFIX}/boost/current

meson compile -C .build
