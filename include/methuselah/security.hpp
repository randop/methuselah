#pragma once

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace methuselah {

// Ownership accepted by Security::trusted_executable(), trusted_file(), and
// trusted_directory(). Root is the default because system packages are
// installed by the administrator. The AWS verifier adds its dedicated service
// account so a non-root AWS CLI install can be trusted without opening the
// door to arbitrary user-owned files.
struct TrustPolicy {
  std::vector<uid_t> owners{0};
};

// Outcome of every Security::verify_*() call: a standard error condition
// plus a short reason. `std::errc{}` means success, `permission_denied` means
// the caller failed a security policy check, and `io_error` means verification
// could not be completed.
//
// `reason` is a view and owns nothing, so it must outlive the verdict. The
// constructor only accepts string literals (static storage), which makes a
// dangling view impossible by construction: a std::string, a char pointer, or
// any other runtime text is rejected at compile time. Put variable detail
// (a path, a variable name) in a trace log, not in the reason.
//
//   const auto [result, reason] = security.verify_git();
struct SecurityVerdict {
  std::errc result = std::errc::io_error;
  std::string_view reason{};

  constexpr SecurityVerdict() noexcept = default;

  template <std::size_t N>
  constexpr SecurityVerdict(std::errc outcome,
                            const char (&literal)[N]) noexcept
      : result(outcome), reason(literal) {}

  [[nodiscard]] constexpr bool passed() const noexcept {
    return result == std::errc{};
  }
};

// Result of Security::read_trusted_file(). The stage that failed is kept so
// each caller can word its own error.
struct TrustedFileContent {
  enum class Status : std::uint8_t {
    ok,
    absent, // the file does not exist (callers decide whether that is fine)
    cannot_inspect, // lstat failed for another reason
    untrusted,      // path, owner or mode is not trusted
    cannot_open,
    cannot_read,
    too_large,
  };

  Status status = Status::cannot_inspect;
  std::string data; // only meaningful when status == ok
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

  // Reads a small policy file (pin list, signer list) only if it is trusted:
  // the path passes trusted_file(), it is opened without following a final
  // symlink, and the opened descriptor is itself a regular file owned by an
  // allowed account without group/other write access (so a swap between the
  // path check and the open is caught). At most `max_bytes` are read.
  [[nodiscard]] static TrustedFileContent
  read_trusted_file(const std::filesystem::path &file, std::size_t max_bytes,
                    const TrustPolicy &policy = {});

  [[nodiscard]] SecurityVerdict verify_git() const;
  [[nodiscard]] SecurityVerdict verify_gpg() const;
  [[nodiscard]] SecurityVerdict verify_ssh() const;

  // Verifies that the supplied process is an untampered AWS CLI v2 owned by
  // root or the dedicated service account (see AwsCliVerifier).
  [[nodiscard]] SecurityVerdict verify_aws(pid_t pid) const;
};

} // namespace methuselah
