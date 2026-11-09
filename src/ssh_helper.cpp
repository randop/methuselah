#include "methuselah/ssh_helper.hpp"
#include "methuselah/trusted_executable.hpp"

namespace methuselah {

std::optional<SSHhelper::Path> SSHhelper::locateBinary(std::string_view name) {
  if (name.empty() || name.find('/') != std::string_view::npos ||
      name.find('\0') != std::string_view::npos) {
    return std::nullopt;
  }
  return detail::trustedExecutable(Path("/usr/bin") / std::string(name));
}

} // namespace methuselah
