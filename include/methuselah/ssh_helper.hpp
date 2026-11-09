#pragma once

#include <filesystem>
#include <optional>
#include <string_view>

namespace methuselah {

class SSHhelper {
public:
  using Path = std::filesystem::path;

  SSHhelper() = default;

  // Finds an executable named `name` on PATH. Returns its canonical path.
  [[nodiscard]] static std::optional<Path>
  locateBinary(std::string_view name = "ssh");
};

} // namespace methuselah
