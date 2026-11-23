#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string_view>

namespace methuselah {

enum class SecurityVerificationResult : std::uint8_t {
  passed,
  failed,
  faulted
};

// Outcome of every Security::verify_*() call: a verdict plus a short reason.
//
// `reason` is a view and owns nothing, so it must outlive the verdict. The
// constructor only accepts string literals (static storage), which makes a
// dangling view impossible by construction: a std::string, a char pointer, or
// any other runtime text is rejected at compile time. Put variable detail
// (a path, a variable name) in a trace log, not in the reason.
//
//   const auto [result, reason] = security.verify_git();
struct SecurityVerdict {
  SecurityVerificationResult result = SecurityVerificationResult::faulted;
  std::string_view reason{};

  constexpr SecurityVerdict() noexcept = default;

  template <std::size_t N>
  constexpr SecurityVerdict(SecurityVerificationResult outcome,
                            const char (&literal)[N]) noexcept
      : result(outcome), reason(literal) {}

  [[nodiscard]] constexpr bool passed() const noexcept {
    return result == SecurityVerificationResult::passed;
  }
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

  [[nodiscard]] SecurityVerdict verify_git() const;
  [[nodiscard]] SecurityVerdict verify_gpg() const;
  [[nodiscard]] SecurityVerdict verify_ssh() const;

  // Verifies that the calling process is an untampered, root-owned AWS CLI v2
  // (see AwsCliVerifier).
  [[nodiscard]] SecurityVerdict verify_aws() const;
};

} // namespace methuselah
