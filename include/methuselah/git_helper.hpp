#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace methuselah {

class GitHelper final {
public:
  using Path = std::filesystem::path;

  // Returns the directory reported by `git --exec-path`.
  [[nodiscard]] static std::optional<Path>
  execPath(std::string_view gitExecutable = "git");

  // Returns git-remote-http if it exists and is executable.
  [[nodiscard]] static std::optional<Path>
  locateRemoteHttp(std::string_view gitExecutable = "git");

  // Convenience check for git-remote-http availability.
  [[nodiscard]] static bool
  hasRemoteHttp(std::string_view gitExecutable = "git");

private:
  [[nodiscard]] static std::optional<std::string>
  runGitExecPath(std::string_view gitExecutable);
};

} // namespace methuselah
