#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>

namespace methuselah {

enum class SecurityVerificationResult : std::uint8_t {
  passed,
  failed,
  faulted
};

class Security {
public:
  Security() = default;

  Security(const Security &) = delete;
  Security &operator=(const Security &) = delete;
  Security(Security &&) = delete;
  Security &operator=(Security &&) = delete;

  // Trust only root-owned installations without group/other write access.
  // Inspect every traversed component, including symlink targets before any
  // '..' components are collapsed. Canonicalization alone would hide those
  // components.
  [[nodiscard]] static std::optional<std::filesystem::path>
  trusted_executable(const std::filesystem::path &candidate);

  [[nodiscard]] SecurityVerificationResult verify_git() const;
  [[nodiscard]] SecurityVerificationResult verify_gpg() const;
  [[nodiscard]] SecurityVerificationResult verify_ssh() const;
};

} // namespace methuselah
