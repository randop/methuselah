#include "methuselah/ssh_helper.hpp"
#include "methuselah/process_info.hpp"

#include <unistd.h>

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

namespace methuselah {

std::optional<SSHhelper::Path> SSHhelper::locateBinary(std::string_view name) {
  // Reject names that would escape PATH lookup or contain NULs.
  if (name.empty() || name.find('/') != std::string_view::npos ||
      name.find('\0') != std::string_view::npos) {
    return std::nullopt;
  }

  const char *pathEnv = std::getenv("PATH");
  if (pathEnv == nullptr) {
    return std::nullopt;
  }

  std::string_view remaining(pathEnv);
  while (!remaining.empty()) {
    const auto colon = remaining.find(':');
    const std::string_view dir = remaining.substr(0, colon);
    remaining.remove_prefix(colon == std::string_view::npos ? remaining.size()
                                                            : colon + 1);

    // An empty PATH entry means the current directory; skip it for safety.
    if (dir.empty()) {
      continue;
    }

    const Path candidate = Path(std::string(dir)) / std::string(name);

    std::error_code ec;
    if (!std::filesystem::is_regular_file(candidate, ec) || ec) {
      continue;
    }
    if (::access(candidate.c_str(), X_OK) != 0) {
      continue;
    }

    std::error_code canonicalEc;
    Path canonical = std::filesystem::canonical(candidate, canonicalEc);
    return canonicalEc ? candidate : canonical;
  }

  return std::nullopt;
}
} // namespace methuselah
