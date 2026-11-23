#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

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

  // Same trust rules as trusted_executable(), for a regular file that is only
  // mapped or read (shared libraries, pin lists) and need not be executable.
  [[nodiscard]] static std::optional<std::filesystem::path>
  trusted_file(const std::filesystem::path &candidate);

  [[nodiscard]] static std::optional<std::filesystem::path>
  trusted_directory(const std::filesystem::path &candidate);

  [[nodiscard]] SecurityVerificationResult verify_git() const;
  [[nodiscard]] SecurityVerificationResult verify_gpg() const;
  [[nodiscard]] SecurityVerificationResult verify_ssh() const;

  // Verifies that the calling process is an untampered, root-owned AWS CLI v2
  // (see AwsCliVerifier). `reason`, when given, receives a short diagnostic.
  [[nodiscard]] SecurityVerificationResult
  verify_aws(std::string *reason = nullptr) const;
};

} // namespace methuselah
