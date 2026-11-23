#pragma once

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string_view>
#include <vector>

namespace methuselah {

enum class SecurityVerificationResult : std::uint8_t {
  passed,
  failed,
  faulted
};

// Ownership accepted by Security::trusted_executable(), trusted_file(), and
// trusted_directory(). Root is the default because system packages are
// installed by the administrator. The AWS verifier adds its dedicated service
// account so a non-root AWS CLI install can be trusted without opening the
// door to arbitrary user-owned files.
struct TrustPolicy {
  std::vector<uid_t> owners{0};
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

  // Trust only installations owned by an allowed account (root by default)
  // without group/other write access. Inspect every traversed component,
  // including symlink targets before any '..' components are collapsed.
  // Canonicalization alone would hide those components.
  [[nodiscard]] static std::optional<std::filesystem::path>
  trusted_executable(const std::filesystem::path &candidate,
                     const TrustPolicy &policy = {});

  // Same trust rules as trusted_executable(), for a regular file that is only
  // mapped or read (shared libraries, pin lists) and need not be executable.
  [[nodiscard]] static std::optional<std::filesystem::path>
  trusted_file(const std::filesystem::path &candidate,
               const TrustPolicy &policy = {});

  [[nodiscard]] static std::optional<std::filesystem::path>
  trusted_directory(const std::filesystem::path &candidate,
                    const TrustPolicy &policy = {});

  [[nodiscard]] SecurityVerdict verify_git() const;
  [[nodiscard]] SecurityVerdict verify_gpg() const;
  [[nodiscard]] SecurityVerdict verify_ssh() const;

  // Verifies that the calling process is an untampered AWS CLI v2 owned by
  // root or the dedicated service account (see AwsCliVerifier).
  [[nodiscard]] SecurityVerdict verify_aws() const;
};

} // namespace methuselah
