#include "methuselah/instance_lock.hpp"

#include "config.h"
#include "methuselah/signal_guard.hpp"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <ctime>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <string>
#include <sys/file.h>
#include <unistd.h>

namespace methuselah {
namespace {

// A stalled holder (for example an unanswered passphrase dialog) must not
// block every later credential_process call for ever.
constexpr std::chrono::seconds kWaitLimit{180};

// flock has no pollable readiness, so waiting is a retry on a short timer.
constexpr timespec kRetryDelay{0, 20'000'000};

std::string lock_path(InstanceLock::Mode mode) {
  const char *runtime_dir = std::getenv("XDG_RUNTIME_DIR");
  const char *suffix =
      mode == InstanceLock::Mode::wait ? "-credential-process" : "";
  if (runtime_dir && *runtime_dir) {
    return std::string(runtime_dir) + "/" PROJECT_NAME + suffix + ".lock";
  }
  return "/tmp/" PROJECT_NAME "-" + std::to_string(::getuid()) + suffix +
         ".lock";
}

// Takes the lock on `fd`, waiting for the current holder. Gives up after
// kWaitLimit, on SIGINT/SIGTERM, or on a locking error. SIGINT and SIGTERM
// stay blocked except while waiting (ppoll swaps the original mask back in
// atomically), so a cancellation cannot slip in between the check and the
// wait.
bool lock_waiting(int fd) {
  sigset_t cancellation, original;
  ::sigemptyset(&cancellation);
  ::sigaddset(&cancellation, SIGINT);
  ::sigaddset(&cancellation, SIGTERM);
  if (::sigprocmask(SIG_BLOCK, &cancellation, &original) != 0) {
    return false;
  }

  bool locked = false;
  const auto deadline = std::chrono::steady_clock::now() + kWaitLimit;
  while (!SignalGuard::received() &&
         std::chrono::steady_clock::now() < deadline) {
    if (::flock(fd, LOCK_EX | LOCK_NB) == 0) {
      locked = true;
      break;
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno != EWOULDBLOCK) {
      break;
    }
    if (::ppoll(nullptr, 0, &kRetryDelay, &original) == -1 && errno != EINTR) {
      break;
    }
  }
  return ::sigprocmask(SIG_SETMASK, &original, nullptr) == 0 && locked &&
         !SignalGuard::received();
}

} // namespace

InstanceLock::InstanceLock(Mode mode) {
  fd_ = ::open(lock_path(mode).c_str(),
               O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd_ < 0) {
    return;
  }

  acquired_ = mode == Mode::wait ? lock_waiting(fd_)
                                 : ::flock(fd_, LOCK_EX | LOCK_NB) == 0;
  if (acquired_) {
    return;
  }

  ::close(fd_);
  fd_ = -1;
  if (mode == Mode::focus_existing) {
    std::system("wmctrl -a \"" PROJECT_NAME "\"");
    std::cerr << "Application is already running. Focused existing instance."
              << std::endl;
  }
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
