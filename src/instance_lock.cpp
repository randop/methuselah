#include "methuselah/instance_lock.hpp"

#include "config.h"
#include "methuselah/signal_guard.hpp"

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <string>
#include <sys/file.h>
#include <time.h>
#include <unistd.h>

namespace methuselah {
namespace {

// A stalled holder (for example an unanswered passphrase dialog) must not
// block every later credential_process call for ever.
constexpr time_t kWaitSeconds = 180;

time_t monotonic_seconds() {
  timespec now{};
  ::clock_gettime(CLOCK_MONOTONIC, &now);
  return now.tv_sec;
}

} // namespace

InstanceLock::InstanceLock(Mode mode) {
  const char *runtime_dir = std::getenv("XDG_RUNTIME_DIR");
  const char *suffix = mode == Mode::wait ? "-credential-process" : "";
  const std::string lock_path =
      runtime_dir && *runtime_dir
          ? std::string(runtime_dir) + "/" PROJECT_NAME + suffix + ".lock"
          : "/tmp/" PROJECT_NAME "-" + std::to_string(::getuid()) + suffix +
                ".lock";
  fd_ = ::open(lock_path.c_str(), O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC,
               0600);
  if (fd_ < 0) {
    acquired_ = false;
    return;
  }

  if (mode == Mode::wait) {
    sigset_t cancellation, original;
    ::sigemptyset(&cancellation);
    ::sigaddset(&cancellation, SIGINT);
    ::sigaddset(&cancellation, SIGTERM);
    if (::sigprocmask(SIG_BLOCK, &cancellation, &original) == 0) {
      bool locked = false;
      const time_t deadline = monotonic_seconds() + kWaitSeconds;
      while (!SignalGuard::received() && monotonic_seconds() < deadline) {
        if (::flock(fd_, LOCK_EX | LOCK_NB) == 0) {
          locked = true;
          break;
        }
        if (errno == EINTR) {
          continue;
        }
        if (errno != EWOULDBLOCK) {
          break;
        }
        // flock has no pollable readiness. Retry on a short timer and restore
        // the original signal mask atomically while waiting for cancellation.
        const timespec retry_delay{0, 20'000'000};
        if (::ppoll(nullptr, 0, &retry_delay, &original) == -1 &&
            errno != EINTR) {
          break;
        }
      }
      if (::sigprocmask(SIG_SETMASK, &original, nullptr) == 0 && locked &&
          !SignalGuard::received()) {
        acquired_ = true;
        return;
      }
    }
    ::close(fd_);
    fd_ = -1;
    return;
  }

  if (::flock(fd_, LOCK_EX | LOCK_NB) == 0) {
    acquired_ = true;
    return;
  }

  ::close(fd_);
  fd_ = -1;
  acquired_ = false;
  std::system("wmctrl -a \"" PROJECT_NAME "\"");
  std::cerr << "Application is already running. Focused existing instance."
            << std::endl;
}

InstanceLock::~InstanceLock() {
  if (fd_ < 0) {
    return;
  }
  ::flock(fd_, LOCK_UN);
  ::close(fd_);
  fd_ = -1;
}

} // namespace methuselah
