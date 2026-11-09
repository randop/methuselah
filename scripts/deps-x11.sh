#!/usr/bin/env bash

# Build the X11 libraries and OpenGL dispatch used by the project under
# $HOME/opt/x11.

# exit on error, error on unset variables, and fail on pipeline errors
set -euo pipefail

OPT_PREFIX="${HOME}/opt"
X11_PREFIX="${OPT_PREFIX}/x11/current"
X11_SRC="${OPT_PREFIX}/x11/src"
X11_DOWNLOADS="${OPT_PREFIX}/x11/downloads"

LOCAL_PKGCONFIG="${HOME}/.local/lib/pkgconfig"
LOCAL_BIN="${HOME}/.local/bin"

mkdir -p "${X11_PREFIX}" "${X11_SRC}" "${X11_DOWNLOADS}"
mkdir -p "${LOCAL_PKGCONFIG}" "${LOCAL_BIN}"

if [ -n "${PKG_CONFIG_PATH+set}" ]; then
  export PKG_CONFIG_PATH="${X11_PREFIX}/lib/pkgconfig:${X11_PREFIX}/share/pkgconfig:${LOCAL_PKGCONFIG}:${PKG_CONFIG_PATH}"
else
  export PKG_CONFIG_PATH="${X11_PREFIX}/lib/pkgconfig:${X11_PREFIX}/share/pkgconfig:${LOCAL_PKGCONFIG}"
fi

if [ -n "${CMAKE_PREFIX_PATH+set}" ]; then
  export CMAKE_PREFIX_PATH="${X11_PREFIX}:${CMAKE_PREFIX_PATH}"
else
  export CMAKE_PREFIX_PATH="${X11_PREFIX}"
fi

BUILD_JOBS="${BUILD_JOBS:-$(nproc)}"
XORG_RELEASE="https://xorg.freedesktop.org/releases/individual"
LIBRARY_MODE=(--enable-static --enable-shared)

# Fetch, configure, and install one package. The check path is an installed
# file that proves the package is already present in the shared X11 prefix.
build_package() {
  local name="$1"
  local version="$2"
  local url="$3"
  local check_path="$4"
  shift 4

  local archive="${X11_DOWNLOADS}/$(basename "${url}")"
  local source="${X11_SRC}/${name}-${version}"

  if [ -e "${X11_PREFIX}/${check_path}" ]; then
    echo "${name}: OK"
    return
  fi

  echo "Compiling ${name} ${version} ..."
  rm -rf "${source}"
  mkdir -p "${source}"

  if [ ! -s "${archive}" ]; then
    wget -c -O "${archive}" "${url}"
  fi
  tar -xf "${archive}" -C "${source}" --strip-components=1

  (
    cd "${source}"
    ./configure --prefix="${X11_PREFIX}" "$@"
    make -j"${BUILD_JOBS}"
    make install
  )

  if [ ! -e "${X11_PREFIX}/${check_path}" ]; then
    echo "ERROR: ${name} did not install ${check_path}" >&2
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Protocol headers and build helpers
# ---------------------------------------------------------------------------
build_package xorgproto 2026.1 \
  "${XORG_RELEASE}/proto/xorgproto-2026.1.tar.xz" \
  share/pkgconfig/xproto.pc

build_package xtrans 1.6.0 \
  "${XORG_RELEASE}/lib/xtrans-1.6.0.tar.xz" \
  share/pkgconfig/xtrans.pc

build_package xcb-proto 1.17.0 \
  "${XORG_RELEASE}/proto/xcb-proto-1.17.0.tar.xz" \
  share/pkgconfig/xcb-proto.pc

build_package libpthread-stubs 0.5 \
  "${XORG_RELEASE}/lib/libpthread-stubs-0.5.tar.xz" \
  lib/pkgconfig/pthread-stubs.pc \
  "${LIBRARY_MODE[@]}"

# ---------------------------------------------------------------------------
# libxcb dependencies and libxcb
# ---------------------------------------------------------------------------
build_package libXau 1.0.12 \
  "${XORG_RELEASE}/lib/libXau-1.0.12.tar.xz" \
  lib/libXau.so \
  "${LIBRARY_MODE[@]}"

build_package libXdmcp 1.1.5 \
  "${XORG_RELEASE}/lib/libXdmcp-1.1.5.tar.xz" \
  lib/libXdmcp.so \
  "${LIBRARY_MODE[@]}"

build_package libxcb 1.17.0 \
  "${XORG_RELEASE}/lib/libxcb-1.17.0.tar.xz" \
  lib/libxcb.so \
  "${LIBRARY_MODE[@]}" \
  --enable-xinput \
  --enable-xkb

# ---------------------------------------------------------------------------
# Xlib and extensions used by raylib/GLFW
# ---------------------------------------------------------------------------
build_package libX11 1.8.14 \
  "${XORG_RELEASE}/lib/libX11-1.8.14.tar.xz" \
  lib/libX11.so \
  "${LIBRARY_MODE[@]}"

build_package libXext 1.3.7 \
  "${XORG_RELEASE}/lib/libXext-1.3.7.tar.xz" \
  lib/libXext.so \
  "${LIBRARY_MODE[@]}"

build_package libXrender 0.9.13 \
  "${XORG_RELEASE}/lib/libXrender-0.9.13.tar.xz" \
  lib/libXrender.so \
  "${LIBRARY_MODE[@]}"

build_package libXfixes 6.0.2 \
  "${XORG_RELEASE}/lib/libXfixes-6.0.2.tar.xz" \
  lib/libXfixes.so \
  "${LIBRARY_MODE[@]}"

build_package libXi 1.8.4 \
  "${XORG_RELEASE}/lib/libXi-1.8.4.tar.xz" \
  lib/libXi.so \
  "${LIBRARY_MODE[@]}"

build_package libXrandr 1.5.5 \
  "${XORG_RELEASE}/lib/libXrandr-1.5.5.tar.xz" \
  lib/libXrandr.so \
  "${LIBRARY_MODE[@]}"

build_package libXcursor 1.2.3 \
  "${XORG_RELEASE}/lib/libXcursor-1.2.3.tar.xz" \
  lib/libXcursor.so \
  "${LIBRARY_MODE[@]}"

build_package libXinerama 1.1.6 \
  "${XORG_RELEASE}/lib/libXinerama-1.1.6.tar.xz" \
  lib/libXinerama.so \
  "${LIBRARY_MODE[@]}"

build_package libXxf86vm 1.1.7 \
  "${XORG_RELEASE}/lib/libXxf86vm-1.1.7.tar.xz" \
  lib/libXxf86vm.so \
  "${LIBRARY_MODE[@]}"

# ---------------------------------------------------------------------------
# OpenGL dispatch (libglvnd), required by raylib through CMake
# ---------------------------------------------------------------------------
GLVND_VERSION=1.7.0
GLVND_URL="https://gitlab.freedesktop.org/glvnd/libglvnd/-/archive/v${GLVND_VERSION}/libglvnd-v${GLVND_VERSION}.tar.gz"
GLVND_ARCHIVE="${X11_DOWNLOADS}/libglvnd-v${GLVND_VERSION}.tar.gz"
GLVND_SOURCE="${X11_SRC}/libglvnd-${GLVND_VERSION}"

if [ -e "${X11_PREFIX}/lib/libGL.so" ]; then
  echo "libglvnd: OK"
else
  echo "Compiling libglvnd ${GLVND_VERSION} ..."
  rm -rf "${GLVND_SOURCE}"
  mkdir -p "${GLVND_SOURCE}"

  if [ ! -s "${GLVND_ARCHIVE}" ]; then
    wget -c -O "${GLVND_ARCHIVE}" "${GLVND_URL}"
  fi
  tar -xf "${GLVND_ARCHIVE}" -C "${GLVND_SOURCE}" --strip-components=1

  (
    cd "${GLVND_SOURCE}"
    meson setup build --prefix="${X11_PREFIX}" --buildtype=release \
      -Dx11=enabled -Dglx=enabled -Degl=false -Dgles1=false -Dgles2=false
    meson compile -C build
    meson install -C build
  )

  if [ ! -e "${X11_PREFIX}/lib/libGL.so" ]; then
    echo "ERROR: libglvnd did not install libGL.so" >&2
    exit 1
  fi
fi

# Make the pkg-config files visible to scripts/compile.sh and other shells.
for pc_dir in "${X11_PREFIX}/lib/pkgconfig" "${X11_PREFIX}/share/pkgconfig"; do
  for pc_file in "${pc_dir}"/*.pc; do
    [ -e "${pc_file}" ] || continue
    ln -sf "${pc_file}" "${LOCAL_PKGCONFIG}/$(basename "${pc_file}")"
  done
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== X11 stack ready ==="
echo "X11_PREFIX: $X11_PREFIX"
echo "PKG_CONFIG_PATH: $PKG_CONFIG_PATH"
echo "CMAKE_PREFIX_PATH: $CMAKE_PREFIX_PATH"
echo ""
echo "Versions (pkg-config):"
pkg-config --modversion x11 2>/dev/null || echo "  x11: (not found)"
pkg-config --modversion xext 2>/dev/null || echo "  xext: (not found)"
pkg-config --modversion xrandr 2>/dev/null || echo "  xrandr: (not found)"
pkg-config --modversion xinerama 2>/dev/null || echo "  xinerama: (not found)"
pkg-config --modversion xcursor 2>/dev/null || echo "  xcursor: (not found)"
pkg-config --modversion xi 2>/dev/null || echo "  xi: (not found)"
pkg-config --modversion gl 2>/dev/null || echo "  gl: (not found)"
echo ""
echo "Static libraries:"
ls -1 \
  "${X11_PREFIX}/lib/libX11.a" \
  "${X11_PREFIX}/lib/libXext.a" \
  "${X11_PREFIX}/lib/libXrandr.a" \
  "${X11_PREFIX}/lib/libXinerama.a" \
  "${X11_PREFIX}/lib/libXcursor.a" \
  "${X11_PREFIX}/lib/libXi.a" 2>/dev/null || true
echo ""
echo "Set CMAKE_PREFIX_PATH when configuring the project if it is not already set:"
echo "  export CMAKE_PREFIX_PATH=\"${X11_PREFIX}\${CMAKE_PREFIX_PATH:+:\${CMAKE_PREFIX_PATH}}\""
