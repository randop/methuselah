#pragma once

#include "methuselah/secure_memory.hpp"

#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace methuselah {

struct DockerParseResult;

// Credentials in the format Docker's external credential helper protocol
// expects.
//
// Stored (GPG-encrypted) as key=value lines. The short names and the
// `docker_`-prefixed names are accepted, case-insensitively, and `_`/`-` are
// ignored:
//
//   username=...   (user, login)                  required
//   password=...   (secret, token, identitytoken) required
//
// Unknown keys, duplicates, empty values, and values containing control
// characters are rejected. Values are escaped when written as JSON, so quotes,
// backslashes, and other printable characters are safe.
class DockerCredentials {
public:
  DockerCredentials() = default;
  ~DockerCredentials() { wipe(); }

  DockerCredentials(const DockerCredentials &) = delete;
  DockerCredentials &operator=(const DockerCredentials &) = delete;
  DockerCredentials(DockerCredentials &&other) noexcept
      : username_(std::move(other.username_)),
        secret_(std::move(other.secret_)) {
    other.wipe();
  }
  DockerCredentials &operator=(DockerCredentials &&other) noexcept {
    if (this != &other) {
      wipe();
      username_ = std::move(other.username_);
      secret_ = std::move(other.secret_);
      other.wipe();
    }
    return *this;
  }

  // Parses credentials and returns a result with a standard error condition,
  // a short reason, and the parsed credentials. On failure `credentials` is
  // empty.
  [[nodiscard]] static DockerParseResult parse(std::string_view text);

  // {"ServerURL":"...","Username":"...","Secret":"..."} followed by a newline,
  // in guarded memory.
  [[nodiscard]] SecureString
  to_credential_helper_json(std::string_view server_url) const;

  [[nodiscard]] const SecureString &username() const noexcept {
    return username_;
  }
  [[nodiscard]] const SecureString &secret() const noexcept { return secret_; }

private:
  void wipe() noexcept {
    secure_clear(username_);
    secure_clear(secret_);
  }

  SecureString username_;
  SecureString secret_;
};

// Outcome of DockerCredentials::parse(): a standard error condition plus a
// short reason, mirroring SecurityVerdict, together with the parsed
// credentials. `reason` is a view and owns nothing, so it must outlive the
// result.
struct DockerParseResult {
  std::errc result = std::errc::io_error;
  std::string_view reason{};
  DockerCredentials credentials;
};

// A Docker registry server address as the CLI passes it to a credential
// helper. The address is kept in one line of printable ASCII. Brackets are
// allowed only around an IPv6 host.
[[nodiscard]] bool valid_docker_server(std::string_view server);

// Candidate names for a server address, most exact first. The CLI's own
// spelling is tried verbatim, then without the scheme or a trailing slash,
// then the host alone. Docker Hub's several spellings map to the same set.
// Config::gpg_file_for() matches names case-insensitively.
[[nodiscard]] std::vector<std::string>
docker_server_aliases(std::string_view server);

// Candidate `[docker:<...>]` and [docker-ipv6:...] section names, in the same
// order as docker_server_aliases(). IPv6 aliases encode brackets and percent.
[[nodiscard]] std::vector<std::string>
docker_config_sections(std::string_view server);

} // namespace methuselah
