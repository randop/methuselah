```
⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫
⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫🔵⚫⚫🔵⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫🔵⚫⚫⚫⚫⚫⚫🔵⚫⚫⚫⚫
⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫🔵⚫⚫🔵⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫🔵⚫⚫⚫⚫⚫⚫🔵⚫⚫⚫⚫
⚫🔵🔵🔵🔵🔵⚫🔵🔵🔵🔵⚫🔵🔵🔵⚫🔵🔵🔵🔵⚫🔵⚫⚫🔵⚫🔵🔵🔵🔵⚫🔵🔵🔵🔵⚫🔵⚫⚫🔵🔵🔵⚫🔵🔵🔵🔵⚫
⚫🔵⚫🔵⚫🔵⚫🔵⚫⚫🔵⚫⚫🔵⚫⚫🔵⚫⚫🔵⚫🔵⚫⚫🔵⚫🔵⚫⚫⚫⚫🔵⚫⚫🔵⚫🔵⚫⚫⚫⚫🔵⚫🔵⚫⚫🔵⚫
⚫🔵⚫🔵⚫🔵⚫🔵🔵🔵🔵⚫⚫🔵⚫⚫🔵⚫⚫🔵⚫🔵⚫⚫🔵⚫🔵🔵🔵🔵⚫🔵🔵🔵🔵⚫🔵⚫🔵🔵🔵🔵⚫🔵⚫⚫🔵⚫
⚫🔵⚫🔵⚫🔵⚫🔵⚫⚫⚫⚫⚫🔵⚫⚫🔵⚫⚫🔵⚫🔵⚫⚫🔵⚫⚫⚫⚫🔵⚫🔵⚫⚫⚫⚫🔵⚫🔵⚫⚫🔵⚫🔵⚫⚫🔵⚫
⚫🔵⚫🔵⚫🔵⚫🔵🔵🔵🔵⚫⚫🔵🔵⚫🔵⚫⚫🔵⚫🔵🔵🔵🔵⚫🔵🔵🔵🔵⚫🔵🔵🔵🔵⚫🔵⚫🔵🔵🔵🔵⚫🔵⚫⚫🔵⚫
⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫⚫
```

Credential helper for Git, GPG, SSH

### Dependencies
```bash
# For debian-based
apt install \
  build-essential \
  pkg-config \
  git \
  meson \
  ninja-build \
  cmake \
  libboost-filesystem-dev \
  libgpgme-dev \
  libgpg-error-dev \
  libassuan-dev \
  libasound2-dev \
  libx11-dev \
  libgl-dev \
  libxrandr-dev \
  libxinerama-dev \
  libxcursor-dev \
  libxi-dev

# For Artix/Arch
pacman -Syy \
  base-devel \
  meson \
  cmake \
  pkgconfig \
  git \
  alsa-lib \
  mesa \
  gpgme \
  libxi \
  libassuan \
  xorg-xrandr \
  libxinerama \
  libxcursor
```

Meson 1.0.1 or newer is required to build; `scripts/format.sh` requires
Meson 1.5 or newer and `clang-format`.

Boost 1.90.0 or newer (including the Filesystem library) is required. If your
distribution provides an older version, install it from the
[official Boost release](https://www.boost.org/releases/1.90.0/)
(`curl` and `bzip2` are needed for these commands):

```bash
curl -fLO https://archives.boost.io/release/1.90.0/source/boost_1_90_0.tar.bz2
tar -xjf boost_1_90_0.tar.bz2
cd boost_1_90_0
./bootstrap.sh --prefix="$HOME/opt/boost/current" --with-libraries=filesystem
./b2 install
cd ..
export BOOST_ROOT="$HOME/opt/boost/current"
export CMAKE_PREFIX_PATH="$BOOST_ROOT${CMAKE_PREFIX_PATH:+:$CMAKE_PREFIX_PATH}"
export LD_LIBRARY_PATH="$BOOST_ROOT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
```

Keep these environment variables set when configuring, building, and running
Methuselah with the locally installed Boost.
