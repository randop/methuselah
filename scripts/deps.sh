#!/bin/sh

# exit on error, error on unset variables
set -eu

OPT_PREFIX=$HOME/opt

if [ ! -d "${OPT_PREFIX}" ]; then
  mkdir -p ${OPT_PREFIX}
else
  echo "${OPT_PREFIX} directory: OK"
fi

LOCAL_PKGCONFIG=${HOME}/.local/lib/pkgconfig
if [ ! -d "${LOCAL_PKGCONFIG}" ]; then
  mkdir -p ${LOCAL_PKGCONFIG}
fi

LOCAL_BIN=${HOME}/.local/bin
if [ ! -d "${LOCAL_BIN}" ]; then
  mkdir -p ${LOCAL_BIN}
fi

if [ -n "${PKG_CONFIG_PATH+set}" ]; then
  export PKG_CONFIG_PATH="${LOCAL_PKGCONFIG}:${PKG_CONFIG_PATH}"
else
  export PKG_CONFIG_PATH=$LOCAL_PKGCONFIG
fi

BOOST_VERSION=v1.91.0
BOOST_STRING=boost-1.91.0-1
mkdir -p ${OPT_PREFIX}/boost/current
cd ${OPT_PREFIX}/boost
if [ ! -f "${OPT_PREFIX}/boost/current/lib/libboost_atomic.so" ]; then
  echo "Downloading boost $BOOST_VERSION ..."
  wget -c "https://github.com/boostorg/boost/releases/download/boost-1.91.0-1/boost-1.91.0-1-b2-nodocs.tar.gz"
  mkdir -p ${OPT_PREFIX}/boost/current
  mkdir -vp ${OPT_PREFIX}/boost/${BOOST_VERSION}
  tar xzf ${OPT_PREFIX}/boost/boost-1.91.0-1-b2-nodocs.tar.gz -C ${OPT_PREFIX}/boost/${BOOST_VERSION}
  cd ${OPT_PREFIX}/boost/${BOOST_VERSION}/${BOOST_STRING}/

  if [ ! -f "${OPT_PREFIX}/boost/$BOOST_VERSION/$BOOST_STRING/project-config.jam" ]; then
    echo "Processing boost $BOOST_VERSION bootstrap..."
    ./bootstrap.sh --prefix=${OPT_PREFIX}/boost/current
  fi
fi

if [ ! -f "${OPT_PREFIX}/boost/current/lib/libboost_atomic.so" ]; then
  echo "Compiling boost..."
  ${OPT_PREFIX}/boost/${BOOST_VERSION}/${BOOST_STRING}/b2 -j$(nproc) threading=multi variant=release install
else
  echo "boost: OK"
fi

export BOOST_ROOT=${OPT_PREFIX}/boost/current

if [ -n "${CMAKE_PREFIX_PATH+set}" ]; then
  CMAKE_PREFIX_PATH="${OPT_PREFIX}/boost/current:${CMAKE_PREFIX_PATH}"
else
  CMAKE_PREFIX_PATH="${OPT_PREFIX}/boost/current"
fi
export CMAKE_PREFIX_PATH

# ---------------------------------------------------------------------------
# libgpg-error (gpgrt) 1.61
# ---------------------------------------------------------------------------
GPG_ERROR_VERSION=1.61
GPG_ERROR_TAG=libgpg-error-1.61
if [ ! -f "${OPT_PREFIX}/libgpg-error/current/lib/libgpg-error.a" ]; then
  echo "Compiling libgpg-error ${GPG_ERROR_VERSION} ..."
  mkdir -p ${OPT_PREFIX}/libgpg-error/current
  rm -rf ${OPT_PREFIX}/libgpg-error/current/*
  rm -rf ${OPT_PREFIX}/libgpg-error/${GPG_ERROR_VERSION}
  git clone -b ${GPG_ERROR_TAG} https://github.com/gpg/libgpg-error.git \
    ${OPT_PREFIX}/libgpg-error/${GPG_ERROR_VERSION}
  rm -rf ${OPT_PREFIX}/libgpg-error/${GPG_ERROR_VERSION}/.git
  rm -rf ${OPT_PREFIX}/libgpg-error/${GPG_ERROR_VERSION}/.github
  cd ${OPT_PREFIX}/libgpg-error/${GPG_ERROR_VERSION}
  ./autogen.sh
  ./configure \
    --prefix=${OPT_PREFIX}/libgpg-error/current \
    --enable-static \
    --disable-shared \
    --disable-nls \
    --disable-doc \
    --disable-languages
  make -j$(nproc)
  make install
  rm -f ${LOCAL_PKGCONFIG}/gpg-error.pc
  echo "Checking compiled libgpg-error..." &&
    file ${OPT_PREFIX}/libgpg-error/current/lib/libgpg-error.a
else
  echo "libgpg-error: OK"
fi

if [ ! -f "${LOCAL_PKGCONFIG}/gpg-error.pc" ]; then
  ln -sv ${OPT_PREFIX}/libgpg-error/current/lib/pkgconfig/gpg-error.pc \
    ${LOCAL_PKGCONFIG}/gpg-error.pc
fi
export CMAKE_PREFIX_PATH="${OPT_PREFIX}/libgpg-error/current${CMAKE_PREFIX_PATH:+:${CMAKE_PREFIX_PATH}}"
export PKG_CONFIG_PATH="${OPT_PREFIX}/libgpg-error/current/lib/pkgconfig:${PKG_CONFIG_PATH}"

# ---------------------------------------------------------------------------
# libassuan 3.0.2
# ---------------------------------------------------------------------------
LIBASSUAN_VERSION=3.0.2
LIBASSUAN_TAG=libassuan-3.0.2
if [ ! -f "${OPT_PREFIX}/libassuan/current/lib/libassuan.a" ]; then
  echo "Compiling libassuan ${LIBASSUAN_VERSION} ..."
  mkdir -p ${OPT_PREFIX}/libassuan/current
  rm -rf ${OPT_PREFIX}/libassuan/current/*
  rm -rf ${OPT_PREFIX}/libassuan/${LIBASSUAN_VERSION}
  git clone -b ${LIBASSUAN_TAG} https://github.com/gpg/libassuan.git \
    ${OPT_PREFIX}/libassuan/${LIBASSUAN_VERSION}
  rm -rf ${OPT_PREFIX}/libassuan/${LIBASSUAN_VERSION}/.git
  rm -rf ${OPT_PREFIX}/libassuan/${LIBASSUAN_VERSION}/.github
  cd ${OPT_PREFIX}/libassuan/${LIBASSUAN_VERSION}
  ./autogen.sh
  ./configure \
    --prefix=${OPT_PREFIX}/libassuan/current \
    --enable-static \
    --disable-shared \
    --disable-doc \
    --with-libgpg-error-prefix=${OPT_PREFIX}/libgpg-error/current
  make -j$(nproc)
  make install
  rm -f ${LOCAL_PKGCONFIG}/libassuan.pc
  echo "Checking compiled libassuan..." &&
    file ${OPT_PREFIX}/libassuan/current/lib/libassuan.a
else
  echo "libassuan: OK"
fi

if [ ! -f "${LOCAL_PKGCONFIG}/libassuan.pc" ]; then
  ln -sv ${OPT_PREFIX}/libassuan/current/lib/pkgconfig/libassuan.pc \
    ${LOCAL_PKGCONFIG}/libassuan.pc
fi
export CMAKE_PREFIX_PATH="${OPT_PREFIX}/libassuan/current:${CMAKE_PREFIX_PATH}"
export PKG_CONFIG_PATH="${OPT_PREFIX}/libassuan/current/lib/pkgconfig:${PKG_CONFIG_PATH}"

# Adjust PATH to avoid system libgpg-error conflicts
export PATH="${OPT_PREFIX}/libgpg-error/current/bin:$PATH"

# ---------------------------------------------------------------------------
# gpgme 2.2.0
# ---------------------------------------------------------------------------
GPGME_VERSION=2.2.0
GPGME_TAG=gpgme-2.2.0
if [ ! -f "${OPT_PREFIX}/gpgme/current/lib/libgpgme.a" ]; then
  echo "Compiling gpgme ${GPGME_VERSION} ..."
  mkdir -p ${OPT_PREFIX}/gpgme/current
  rm -rf ${OPT_PREFIX}/gpgme/current/*
  rm -rf ${OPT_PREFIX}/gpgme/${GPGME_VERSION}
  git clone -b ${GPGME_TAG} https://github.com/gpg/gpgme.git \
    ${OPT_PREFIX}/gpgme/${GPGME_VERSION}
  rm -rf ${OPT_PREFIX}/gpgme/${GPGME_VERSION}/.git
  rm -rf ${OPT_PREFIX}/gpgme/${GPGME_VERSION}/.github
  cd ${OPT_PREFIX}/gpgme/${GPGME_VERSION}
  ./autogen.sh
  ./configure \
    --prefix=${OPT_PREFIX}/gpgme/current \
    --enable-static \
    --disable-shared \
    --enable-languages= \
    --disable-gpg-test \
    --disable-gpgsm-test \
    --disable-g13-test \
    --disable-gpgconf-test \
    --with-libgpg-error-prefix=${OPT_PREFIX}/libgpg-error/current \
    --with-libassuan-prefix=${OPT_PREFIX}/libassuan/current \
    MAKEINFO=true
  make -j$(nproc)
  make install
  rm -f ${LOCAL_PKGCONFIG}/gpgme.pc
  echo "Checking compiled gpgme..." &&
    file ${OPT_PREFIX}/gpgme/current/lib/libgpgme.a
else
  echo "gpgme: OK"
fi

if [ ! -f "${LOCAL_PKGCONFIG}/gpgme.pc" ]; then
  ln -sv ${OPT_PREFIX}/gpgme/current/lib/pkgconfig/gpgme.pc \
    ${LOCAL_PKGCONFIG}/gpgme.pc
fi
export CMAKE_PREFIX_PATH="${OPT_PREFIX}/gpgme/current:${CMAKE_PREFIX_PATH}"
export PKG_CONFIG_PATH="${OPT_PREFIX}/gpgme/current/lib/pkgconfig:${PKG_CONFIG_PATH}"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== GPG stack ready ==="
echo "PKG_CONFIG_PATH: $PKG_CONFIG_PATH"
echo "CMAKE_PREFIX_PATH: $CMAKE_PREFIX_PATH"
echo ""
echo "Versions (pkg-config):"
pkg-config --modversion gpg-error 2>/dev/null || echo "  gpg-error: (not found)"
pkg-config --modversion libassuan 2>/dev/null || echo "  libassuan: (not found)"
pkg-config --modversion gpgme 2>/dev/null || echo "  gpgme: (not found)"
echo ""
echo "Static libraries:"
ls -1 ${OPT_PREFIX}/libgpg-error/current/lib/libgpg-error.a \
  ${OPT_PREFIX}/libassuan/current/lib/libassuan.a \
  ${OPT_PREFIX}/gpgme/current/lib/libgpgme.a 2>/dev/null || true
