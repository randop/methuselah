# Building project

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
  libsodium-dev \
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
  libsodium \
  xorg-xrandr \
  libxinerama \
  libxcursor
```

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:fce60f66e3fe4c13020a123ecebedc8bf52f35f9eaf0b410af97283b49bd1e4a -->

Meson 1.0.1 or newer is required to build; `scripts/format.sh` requires
Meson 1.5 or newer and `clang-format`.

libsodium 1.0.22 or newer is required, built as a static library
(`libsodium.a`). If your distribution does not supply it, run the local
dependency setup from the repository root:

```bash
./scripts/deps.sh
./scripts/compile.sh
```

The setup script also builds Boost and the GPG dependencies. It installs
libsodium 1.0.22 under `$HOME/opt/libsodium/current` with
`--enable-static --disable-shared` and links its `libsodium.pc` into
`$HOME/.local/lib/pkgconfig`. The compile script adds that directory to
`PKG_CONFIG_PATH` so Meson can find the local archive through pkg-config.
If `.build` was already configured with a different installation, recreate
it so Meson detects the new dependency.

<!-- /coderabbit-ai-generated:v1 -->

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
