#include "methuselah/memory_guard.hpp"
#include "methuselah/secure_memory.hpp"

#include <sodium.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

extern char **environ;

namespace methuselah {

namespace {

// Remove dynamic-loader injection and debugging hooks from the environment.
void scrub_environment() noexcept {
  static constexpr const char *kBlocked[] = {
      "LD_PRELOAD",      "LD_LIBRARY_PATH", "LD_AUDIT",     "LD_DEBUG",
      "LD_DEBUG_OUTPUT", "LD_PROFILE",      "LD_BIND_NOW",  "MALLOC_CONF",
      "MALLOC_PERTURB_", "MALLOC_CHECK_",   "MALLOC_TRACE",
  };
  for (const char *name : kBlocked) {
    ::unsetenv(name);
  }
}

} // namespace

bool MemoryGuard::being_traced() noexcept {
  const int fd = ::open("/proc/self/status", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return false;
  }
  char buf[4096];
  const ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
  ::close(fd);
  if (n <= 0) {
    return false;
  }
  buf[n] = '\0';
  const char *line = std::strstr(buf, "TracerPid:");
  if (line == nullptr) {
    return false;
  }
  return std::atoi(line + std::strlen("TracerPid:")) != 0;
}

bool MemoryGuard::harden() noexcept {
  if (::sodium_init() < 0) {
    std::fputs("FATAL: libsodium initialisation failed\n", stderr);
    return false;
  }

  if (being_traced()) {
    std::fputs("FATAL: debugger/tracer detected, refusing to run\n", stderr);
    return false;
  }

  // Disable core dumps and ptrace/proc-mem access from same-uid processes.
  if (::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
    std::fputs("WARN: prctl(PR_SET_DUMPABLE) failed\n", stderr);
  }

  const rlimit no_core{0, 0};
  if (::setrlimit(RLIMIT_CORE, &no_core) != 0) {
    std::fputs("WARN: setrlimit(RLIMIT_CORE) failed\n", stderr);
  }

  if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    std::fputs("WARN: prctl(PR_SET_NO_NEW_PRIVS) failed\n", stderr);
  }

  scrub_environment();
  return true;
}

void MemoryGuard::scramble(void *ptr, unsigned long n) noexcept {
  if (ptr == nullptr || n == 0) {
    return;
  }
  ::randombytes_buf(ptr, n);
  ::sodium_memzero(ptr, n);
}

} // namespace methuselah
