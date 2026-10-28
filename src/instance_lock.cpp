#include "methuselah/instance_lock.hpp"

#include "config.h"

#include <cstdlib>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <sys/file.h>
#include <unistd.h>

namespace methuselah {
InstanceLock::InstanceLock() {
  const char *runtime_dir = std::getenv("XDG_RUNTIME_DIR");
  const std::string lock_path =
      runtime_dir && *runtime_dir
          ? std::string(runtime_dir) + "/" PROJECT_NAME ".lock"
          : "/tmp/" PROJECT_NAME "-" + std::to_string(::getuid()) + ".lock";
  fd_ = ::open(lock_path.c_str(), O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd_ < 0) {
    acquired_ = false;
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
