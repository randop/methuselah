#!/usr/bin/env bash

# Install AWS CLI v2 for the Methuselah credential helper.
#
# The CLI is owned by the unprivileged `methuselah` system user and the
# `users` group. Members of `users` can read and execute it, but cannot
# modify it. Run this script as your normal user; it asks sudo for the
# system changes.

set -euo pipefail

SERVICE_USER=methuselah
SERVICE_GROUP=users
INSTALL_ROOT=/opt/methuselah/aws-cli
BIN_DIR=/usr/local/bin
PIN_DIR=/etc/methuselah
PIN_FILE=$PIN_DIR/aws-cli.sha256

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

member_of() {
  id -nG "$1" | tr ' ' '\n' | grep -qx "$2"
}

process_in_group() {
  id -nG | tr ' ' '\n' | grep -qx "$1"
}

[ "$(uname -s)" = "Linux" ] || die "this installer supports Linux only"
[ "$(id -u)" -ne 0 ] || die "run this script as a normal user, not root"
[ "$(id -un)" != "$SERVICE_USER" ] ||
  die "run this script as the account that will use AWS, not $SERVICE_USER"

for tool in curl unzip sha256sum getent sudo id install; do
  command -v "$tool" >/dev/null 2>&1 ||
    die "required command not found: $tool"
done

case "$(uname -m)" in
x86_64 | amd64) aws_arch=x86_64 ;;
aarch64 | arm64) aws_arch=aarch64 ;;
*) die "unsupported architecture: $(uname -m)" ;;
esac

check_link() {
  if [ -e "$1" ] && [ ! -L "$1" ]; then
    die "$1 exists and is not a symlink; remove or move it first"
  fi
}

check_link "$BIN_DIR/aws"
check_link "$BIN_DIR/aws_completer"

if ! getent group "$SERVICE_GROUP" >/dev/null; then
  printf 'Creating system group %s\n' "$SERVICE_GROUP"
  sudo groupadd --system "$SERVICE_GROUP"
fi

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  printf 'Creating system user %s\n' "$SERVICE_USER"
  nologin=/usr/sbin/nologin
  [ -x "$nologin" ] || nologin=/sbin/nologin
  [ -x "$nologin" ] || nologin=/bin/false
  sudo useradd --system --gid "$SERVICE_GROUP" \
    --home-dir "/var/lib/$SERVICE_USER" --no-create-home \
    --shell "$nologin" "$SERVICE_USER"
fi

[ "$(id -u "$SERVICE_USER")" -ne 0 ] ||
  die "$SERVICE_USER must not be root"
[ "$(id -u "$SERVICE_USER")" -ne "$(id -u)" ] ||
  die "$SERVICE_USER must be a different account from the caller"

if ! member_of "$SERVICE_USER" "$SERVICE_GROUP"; then
  printf 'Adding %s to %s\n' "$SERVICE_USER" "$SERVICE_GROUP"
  sudo usermod -aG "$SERVICE_GROUP" "$SERVICE_USER"
fi

current_user=$(id -un)
if ! member_of "$current_user" "$SERVICE_GROUP"; then
  printf 'Adding %s to %s\n' "$current_user" "$SERVICE_GROUP"
  sudo usermod -aG "$SERVICE_GROUP" "$current_user"
fi

# The install root is writable only by the service account; the caller gets
# read and execute through the users group.
sudo install -d -o root -g root -m 0755 /opt/methuselah
sudo install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0750 \
  "$INSTALL_ROOT" "$INSTALL_ROOT/bin"
sudo chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_ROOT"
sudo chmod -R u=rwX,g=rX,o= "$INSTALL_ROOT"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/methuselah-aws.XXXXXX")
cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

archive="awscli-exe-linux-$aws_arch.zip"
url="https://awscli.amazonaws.com/$archive"
printf 'Downloading AWS CLI v2 (%s)\n' "$aws_arch"
curl -fL --retry 3 --retry-delay 2 --connect-timeout 15 \
  -o "$tmp/$archive" "$url"
unzip -tq "$tmp/$archive" >/dev/null
unzip -q "$tmp/$archive" -d "$tmp"

# The installer runs as the service account, so it must be able to read the
# extracted tree.
chmod 0755 "$tmp"
chmod -R a+rX "$tmp/aws"

install_args=(-i "$INSTALL_ROOT" -b "$INSTALL_ROOT/bin")
if [ -L "$INSTALL_ROOT/v2/current" ]; then
  install_args+=(--update)
fi
printf 'Installing AWS CLI v2 as %s\n' "$SERVICE_USER"
sudo -u "$SERVICE_USER" "$tmp/aws/install" "${install_args[@]}"

sudo chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_ROOT"
sudo chmod -R u=rwX,g=rX,o= "$INSTALL_ROOT"
sudo test -x "$INSTALL_ROOT/v2/current/dist/aws" ||
  die "AWS CLI installation is incomplete"

install_link() {
  target=$1
  link=$2
  if [ -e "$link" ] && [ ! -L "$link" ]; then
    die "$link exists and is not a symlink; remove or move it first"
  fi
  sudo ln -sfn "$target" "$link"
}

install_link "$INSTALL_ROOT/bin/aws" "$BIN_DIR/aws"
install_link "$INSTALL_ROOT/bin/aws_completer" "$BIN_DIR/aws_completer"

# Pin the launcher. The verifier refuses a CLI that differs from its pin.
sudo install -d -o root -g root -m 0755 "$PIN_DIR"
digest=$(sudo sha256sum "$INSTALL_ROOT/v2/current/dist/aws")
digest=${digest%% *}
printf '%s  %s\n' "$digest" "$BIN_DIR/aws" |
  sudo tee "$PIN_FILE" >/dev/null
sudo chown root:root "$PIN_FILE"
sudo chmod 0644 "$PIN_FILE"

if process_in_group "$SERVICE_GROUP"; then
  "$BIN_DIR/aws" --version
else
  # The group was just added to /etc/group; the current shell does not have it
  # yet. Verify access with the new group without requiring a new login.
  if ! sudo -u "$current_user" -g "$SERVICE_GROUP" \
    "$INSTALL_ROOT/v2/current/dist/aws" --version; then
    printf 'Log out and back in, then run: aws --version\n'
  fi
fi

if ! process_in_group "$SERVICE_GROUP"; then
  printf '\nLog out and back in so your shell joins the %s group.\n' \
    "$SERVICE_GROUP"
fi
printf 'AWS CLI v2 installed in %s (owned by %s:%s)\n' \
  "$INSTALL_ROOT" "$SERVICE_USER" "$SERVICE_GROUP"
printf 'Launcher: %s/aws\n' "$BIN_DIR"
printf 'SHA-256 pin: %s\n' "$PIN_FILE"
