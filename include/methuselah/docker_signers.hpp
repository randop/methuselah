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
// registry's credential file (/etc/methuselah/docker-signers).
//
// Anyone who can write the encrypted file can encrypt credentials of their own
// to the user's public key, but only the holder of the signing key can sign
// them. Because the policy lives in a root-owned file, the user's own
// processes cannot drop the requirement.
//
// File format, one entry per line, '#' comments and blank lines allowed:
//
//   <server> <fingerprint>       e.g.  ghcr.io 0123...(40 or 64 hex digits)
//
// The server address is matched exactly (case-sensitively) as Docker sends it
// to the helper, with the same scheme, trailing-slash, host-only, and Docker
// Hub aliases as the `[docker:<server>]` sections. An absent file, or a server
// without an entry, means no signature is required. A present file that is not
// root-owned, unreadable, too large, or malformed fails closed; entries whose
// aliases overlap (for example `docker.io` and `index.docker.io`) are
// malformed, because they would make the required key depend on lookup order.
class DockerSigners {
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

  // Reads and checks `file`, then looks `server` up.
  [[nodiscard]] static Lookup load(const std::filesystem::path &file,
                                   std::string_view server);

  // Pure helpers, exposed for unit tests. nullopt: malformed, duplicate, or
  // alias-overlapping entries.
  [[nodiscard]] static std::optional<Entries> parse(std::string_view text);
  [[nodiscard]] static Lookup find(const Entries &entries,
                                   std::string_view server);
};

} // namespace methuselah
