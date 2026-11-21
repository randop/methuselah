#!/usr/bin/env bash
# Usage: ./security.sh .build/methuselah [args...]
set -euo pipefail

[[ $# -gt 0 ]] || {
  echo "Usage: $0 executable [args...]" >&2
  exit 2
}
[[ $(uname -s) == Linux ]] || {
  echo "Linux required" >&2
  exit 2
}

tmp=$(mktemp -d)
pid=""
cleanup() {
  if [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  exec 3>&- || true
  rm -rf "$tmp"
}
trap cleanup EXIT

# Keep stdin open without sending real credentials.
mkfifo "$tmp/stdin"
exec 3<>"$tmp/stdin"

# Harmless sentinel: harden() should remove this variable.
env LD_MEMORY_GUARD_TEST=sentinel \
  "$@" <"$tmp/stdin" 3>&- >"$tmp/stdout" 2>"$tmp/stderr" &
pid=$!

# Allow startup/harden() to run.
sleep "${STARTUP_WAIT:-1}"

if ! kill -0 "$pid" 2>/dev/null; then
  echo "INCONCLUSIVE: process exited before inspection."
  echo "Use arguments that keep it running; inspect its output locally."
  exit 2
fi

failures=0
check() {
  local name=$1 actual=$2 expected=$3
  if [[ "$actual" == "$expected" ]]; then
    printf 'PASS: %s\n' "$name"
  else
    printf 'FAIL: %s (got %s, expected %s)\n' \
      "$name" "$actual" "$expected"
    failures=$((failures + 1))
  fi
}

status="/proc/$pid/status"
check "no_new_privs enabled" \
  "$(awk '/^NoNewPrivs:/ {print $2}' "$status")" 1
check "no tracer attached" \
  "$(awk '/^TracerPid:/ {print $2}' "$status")" 0

read -r core_soft core_hard < <(
  awk '/^Max core file size/ {print $5, $6}' "/proc/$pid/limits"
)
check "core soft limit disabled" "$core_soft" 0

# Some kernels expose Dumpable; newer kernels usually do not.
dumpable=$(awk '/^Dumpable:/ {print $2}' "$status")
if [[ -n "$dumpable" ]]; then
  check "process is non-dumpable" "$dumpable" 0
else
  echo "SKIP: kernel does not expose Dumpable in /proc/status."
fi

echo
echo "Not established by these checks:"
echo "- Whether harden() caused settings already inherited from the shell."
echo "- Environment scrubbing: /proc/environ is not a reliable test of unsetenv()."
echo "- Tracer refusal: requires a separate traced run and refusal diagnostics."
echo "- Guard pages, mlock, MADV_DONTDUMP, and zeroization: need unit tests."
echo
printf 'Failed checks: %d\n' "$failures"
((failures == 0))
