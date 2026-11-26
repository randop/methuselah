#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace methuselah {

// Root-owned policy naming the OpenPGP key that must have signed each
// profile's credential file (/etc/methuselah/aws-signers).
//
// Anyone who can write the encrypted file can encrypt keys of their own to
// the user's public key, but only the holder of the signing key can sign
// them. Because the policy lives in a root-owned file, the user's own
// processes cannot drop the requirement.
//
// File format, one entry per line, '#' comments and blank lines allowed:
//
//   <profile> <fingerprint>      e.g.  prod 0123...(40 or 64 hex digits)
//
// An absent file, or a profile without an entry, means no signature is
// required. A present file that is not root-owned, unreadable, too large, or
// malformed fails closed.
class AwsSigners {
public:
  struct Lookup {
    std::errc result = std::errc::io_error;
    std::string_view reason{};
    // Uppercase fingerprint; empty when no signature is required.
    std::string fingerprint;

    [[nodiscard]] bool passed() const noexcept { return result == std::errc{}; }
    [[nodiscard]] bool required() const noexcept {
      return !fingerprint.empty();
    }
  };

  using Entries = std::vector<std::pair<std::string, std::string>>;

  [[nodiscard]] static std::filesystem::path default_file();

  [[nodiscard]] static bool valid_profile_name(std::string_view name);

  // Reads and checks `file`, then looks `profile` up.
  [[nodiscard]] static Lookup load(const std::filesystem::path &file,
                                   std::string_view profile);

  // Pure helpers, exposed for unit tests. nullopt: malformed or duplicate.
  [[nodiscard]] static std::optional<Entries> parse(std::string_view text);
  [[nodiscard]] static Lookup find(const Entries &entries,
                                   std::string_view profile);
};

} // namespace methuselah
