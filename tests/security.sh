#!/usr/bin/env bash
# Usage: ./security.sh executable [args...]
#
# Options:
#   STARTUP_WAIT=1       Seconds before inspecting the process.
#   STOP_WAIT=2          Grace period before cleanup uses SIGKILL.
#   TEST_TRACE=1         Also test refusal to start under strace.
#   TRACE_WAIT=3         Maximum time allowed for tracer refusal.
#   TRACE_REFUSAL_REGEX Required with TEST_TRACE=1; matches the program's
#                       explicit tracer-refusal diagnostic.
#
# Exit codes:
#   0: all performed checks passed (some checks may be skipped)
#   1: one or more checks failed
#   2: invalid configuration or inconclusive inspection
#
# Run only against an executable you trust. No real credentials are sent.

set -Eeuo pipefail
export LC_ALL=C
umask 077

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 2
}

[[ $# -gt 0 ]] || die "Usage: $0 executable [args...]"
[[ $(uname -s) == Linux ]] || die "Linux required"
[[ -d /proc/self ]] || die "/proc must be mounted"

for tool in awk mktemp mkfifo env sleep rm; do
  command -v "$tool" >/dev/null || die "Missing dependency: $tool"
done
command -v -- "$1" >/dev/null || die "Executable not found: $1"

STARTUP_WAIT=${STARTUP_WAIT:-1}
STOP_WAIT=${STOP_WAIT:-2}
TEST_TRACE=${TEST_TRACE:-0}
TRACE_WAIT=${TRACE_WAIT:-3}
TRACE_REFUSAL_REGEX=${TRACE_REFUSAL_REGEX:-}

for value in "$STARTUP_WAIT" "$STOP_WAIT" "$TRACE_WAIT"; do
  [[ $value =~ ^[0-9]+([.][0-9]+)?$ ]] ||
    die "Wait values must be nonnegative numbers"
done
[[ $TEST_TRACE == 0 || $TEST_TRACE == 1 ]] ||
  die "TEST_TRACE must be 0 or 1"

if [[ $TEST_TRACE == 1 ]]; then
  command -v strace >/dev/null || die "TEST_TRACE=1 requires strace"
  command -v grep >/dev/null || die "TEST_TRACE=1 requires grep"
  [[ -n $TRACE_REFUSAL_REGEX ]] ||
    die "Set TRACE_REFUSAL_REGEX to the expected refusal diagnostic"

  # grep returns 1 for a valid expression with no match, 2 for an error.
  if grep -E -- "$TRACE_REFUSAL_REGEX" /dev/null >/dev/null 2>&1; then
    :
  else
    rc=$?
    [[ $rc == 1 ]] || die "Invalid TRACE_REFUSAL_REGEX"
  fi
fi

tmp=$(mktemp -d)
pid=""
watchdog=""
trace_pid=""
trace_watchdog=""

# Zombies still answer kill -0; treat them as exited.
alive() {
  local p=$1 state
  kill -0 "$p" 2>/dev/null || return 1
  state=$(awk '/^State:/ {print $2}' "/proc/$p/status" 2>/dev/null) ||
    return 1
  [[ -n $state && $state != Z && $state != X ]]
}

stop_child() {
  local p=${1:-} timer
  [[ -n $p ]] || return 0

  if alive "$p"; then
    kill -TERM "$p" 2>/dev/null || true
    (
      sleep "$STOP_WAIT"
      kill -KILL "$p" 2>/dev/null || true
    ) &
    timer=$!
    wait "$p" 2>/dev/null || true
    kill "$timer" 2>/dev/null || true
    wait "$timer" 2>/dev/null || true
  else
    wait "$p" 2>/dev/null || true
  fi
}

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  for timer in "$watchdog" "$trace_watchdog"; do
    if [[ -n $timer ]]; then
      kill "$timer" 2>/dev/null || true
      wait "$timer" 2>/dev/null || true
    fi
  done
  stop_child "$trace_pid"
  stop_child "$pid"
  exec 3>&- || true
  rm -rf -- "$tmp"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

passes=0
failures=0
skips=0

pass() {
  printf 'PASS: %s\n' "$*"
  passes=$((passes + 1))
}
fail() {
  printf 'FAIL: %s\n' "$*"
  failures=$((failures + 1))
}
skip() {
  printf 'SKIP: %s\n' "$*"
  skips=$((skips + 1))
}
check() {
  local name=$1 actual=$2 expected=$3
  if [[ -z $actual ]]; then
    skip "$name: field unavailable"
  elif [[ $actual == "$expected" ]]; then
    pass "$name"
  else
    fail "$name (got $actual, expected $expected)"
  fi
}

# Record inherited state so passing checks are not mistaken for proof
# that the application itself established these settings.
shell_nnp=$(awk '/^NoNewPrivs:/ {print $2}' /proc/self/status)
shell_core=$(ulimit -S -c)
printf 'Inherited baseline: NoNewPrivs=%s, core soft limit=%s\n' \
  "${shell_nnp:-unknown}" "$shell_core"

mkfifo "$tmp/stdin"
exec 3<>"$tmp/stdin"

env LD_MEMORY_GUARD_TEST=sentinel \
  "$@" <"$tmp/stdin" 3>&- >"$tmp/stdout" 2>"$tmp/stderr" &
pid=$!

sleep "$STARTUP_WAIT"

if ! alive "$pid"; then
  rc=0
  wait "$pid" || rc=$?
  pid=""
  printf 'INCONCLUSIVE: process exited before inspection (exit %s).\n' "$rc"
  printf 'Use arguments that keep it running without credentials.\n'
  exit 2
fi

# Capture each file once; inaccessible proc files are not evidence
# that a protection is either enabled or disabled.
if status=$(awk '{print}' "/proc/$pid/status" 2>/dev/null); then
  check "no_new_privs enabled" \
    "$(awk '/^NoNewPrivs:/ {print $2}' <<<"$status")" 1
  check "no tracer attached" \
    "$(awk '/^TracerPid:/ {print $2}' <<<"$status")" 0

  dumpable=$(awk '/^Dumpable:/ {print $2}' <<<"$status")
  if [[ -n $dumpable ]]; then
    check "process is non-dumpable" "$dumpable" 0
  else
    skip "non-dumpable flag: kernel does not expose Dumpable"
  fi
else
  skip "status checks: /proc/$pid/status is inaccessible"
fi

if limits=$(awk '{print}' "/proc/$pid/limits" 2>/dev/null); then
  core_soft=$(awk '/^Max core file size/ {print $5}' <<<"$limits")
  core_hard=$(awk '/^Max core file size/ {print $6}' <<<"$limits")
  check "core soft limit disabled" "$core_soft" 0
  printf 'INFO: core hard limit=%s (not required to be zero)\n' \
    "${core_hard:-unknown}"
else
  skip "core limit check: /proc/$pid/limits is inaccessible"
fi

if ! alive "$pid"; then
  printf 'INCONCLUSIVE: process exited during inspection.\n'
  exit 2
fi

# Stop the normal instance before launching another instance.
stop_child "$pid"
pid=""

if [[ $TEST_TRACE == 1 ]]; then
  # Establish that tracing is permitted independently of the application.
  if strace -qq -o "$tmp/trace-probe" -- /bin/true \
    3>&- >/dev/null 2>"$tmp/trace-probe.stderr"; then

    # -D keeps the launched program as this shell's direct child,
    # allowing the timeout to terminate that program, not just strace.
    strace -D -qq -o "$tmp/trace" -- \
      env LD_MEMORY_GUARD_TEST=sentinel "$@" \
      <"$tmp/stdin" 3>&- \
      >"$tmp/trace.stdout" 2>"$tmp/trace.stderr" &
    trace_pid=$!

    (
      sleep "$TRACE_WAIT"
      if alive "$trace_pid"; then
        : >"$tmp/trace-timeout"
        kill -TERM "$trace_pid" 2>/dev/null || true
        sleep "$STOP_WAIT"
        kill -KILL "$trace_pid" 2>/dev/null || true
      fi
    ) &
    trace_watchdog=$!

    trace_rc=0
    wait "$trace_pid" || trace_rc=$?
    trace_pid=""
    kill "$trace_watchdog" 2>/dev/null || true
    wait "$trace_watchdog" 2>/dev/null || true
    trace_watchdog=""

    if [[ -e $tmp/trace-timeout ]]; then
      fail "traced process did not refuse startup before timeout"
    elif ((trace_rc == 0)); then
      fail "traced process exited successfully; refusal not established"
    elif grep -Eq -- "$TRACE_REFUSAL_REGEX" \
      "$tmp/trace.stdout" "$tmp/trace.stderr"; then
      pass "traced startup rejected with explicit diagnostic"
    else
      fail "traced process exited $trace_rc without refusal diagnostic"
    fi
  else
    skip "tracer refusal: strace probe failed or tracing is restricted"
  fi
else
  skip "tracer refusal: enable TEST_TRACE with an expected diagnostic"
fi

cat <<'EOF'

Not established by this script:
- Whether the application caused settings inherited from its launcher.
- Environment scrubbing: /proc/environ cannot reliably verify unsetenv().
- Secret allocation, guard pages, mlock, MADV_DONTDUMP, or zeroization.
- Anti-debugging beyond the optional traced-startup case.
- Hardening of forked children or protection against privileged attackers.

Use dedicated in-process tests for memory protections. Test invalid guard-page
accesses in isolated child processes and verify their termination signals.
Do not use real secrets in test fixtures or diagnostic output.
EOF

printf '\nPassed: %d; Failed: %d; Skipped: %d\n' \
  "$passes" "$failures" "$skips"
((failures == 0))
