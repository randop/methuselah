#pragma once

#include <sys/types.h>

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace methuselah {

class ProcessInfo {
public:
  struct Entry {
    pid_t pid = 0;
    pid_t ppid = 0;
    std::string exe;
    std::string cmdline;
  };

  [[nodiscard]] static pid_t self() noexcept;
  [[nodiscard]] static pid_t parent() noexcept;
  [[nodiscard]] static std::optional<pid_t> parentOf(pid_t pid);
  [[nodiscard]] static std::optional<std::string> exePath(pid_t pid);
  [[nodiscard]] static std::optional<std::string> cmdline(pid_t pid);
  [[nodiscard]] static std::optional<Entry> describe(pid_t pid);
  [[nodiscard]] static std::vector<Entry> ancestry(pid_t pid = 0,
                                                   std::size_t maxDepth = 64);
  [[nodiscard]] static std::optional<Entry> caller();
};

} // namespace methuselah
