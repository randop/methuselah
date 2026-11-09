#pragma once

#include <filesystem>
#include <optional>
#include <string_view>

namespace methuselah {

class SSHhelper {
public:
  using Path = std::filesystem::path;

  SSHhelper() = default;

  // Finds a trusted root-owned executable in /usr/bin, resolving symlinks.
  [[nodiscard]] static std::optional<Path>
  locateBinary(std::string_view name = "ssh");
};

} // namespace methuselah
