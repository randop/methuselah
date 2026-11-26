#include "methuselah/docker_signers.hpp"

#include "methuselah/docker_credentials.hpp"
#include "methuselah/security.hpp"
#include "methuselah/text_util.hpp"

#include <algorithm>
#include <cstddef>
#include <set>

namespace methuselah {
namespace {

constexpr std::size_t kMaxFileBytes = 1U << 16;
// OpenPGP fingerprints: 40 hex digits (SHA-1, v4 keys) or 64 (SHA-256, v5/v6).
constexpr std::size_t kSha1FingerprintLength = 40;
constexpr std::size_t kSha256FingerprintLength = 64;

bool is_fingerprint(std::string_view text) {
  return (text.size() == kSha1FingerprintLength ||
          text.size() == kSha256FingerprintLength) &&
         strutil::is_hex(text);
}

} // namespace

std::filesystem::path DockerSigners::default_file() {
  return "/etc/methuselah/docker-signers";
}

std::optional<DockerSigners::Entries>
DockerSigners::parse(std::string_view text) {
  Entries entries;
  // A server can be spelled several ways, and one entry covers all of them.
  // Two entries that overlap would make the required key depend on lookup
  // order, so reject the policy instead of guessing.
  std::set<std::string> claimed;
  while (!text.empty()) {
    const std::string_view line = strutil::trim(strutil::next_line(text));
    if (line.empty() || line.front() == '#') {
      continue;
    }
    const auto space = line.find_first_of(" \t");
    if (space == std::string_view::npos) {
      return std::nullopt;
    }
    const std::string_view server = line.substr(0, space);
    const std::string_view fingerprint = strutil::trim(line.substr(space));
    if (!valid_docker_server(server) || !is_fingerprint(fingerprint)) {
      return std::nullopt;
    }
    for (const auto &alias : docker_server_aliases(server)) {
      if (!claimed.insert(alias).second) {
        return std::nullopt;
      }
    }
    entries.emplace_back(std::string(server),
                         strutil::ascii_upper(fingerprint));
  }
  return entries;
}

DockerSigners::Lookup DockerSigners::find(const Entries &entries,
                                          std::string_view server) {
  const auto aliases = docker_server_aliases(server);
  for (const auto &[name, fingerprint] : entries) {
    const auto policy_aliases = docker_server_aliases(name);
    if (std::any_of(policy_aliases.begin(), policy_aliases.end(),
                    [&](const auto &alias) {
                      return std::find(aliases.begin(), aliases.end(), alias) !=
                             aliases.end();
                    })) {
      return {std::errc{}, "ok", fingerprint};
    }
  }
  return {std::errc{}, "ok", {}};
}

DockerSigners::Lookup DockerSigners::load(const std::filesystem::path &file,
                                          std::string_view server) {
  using Status = TrustedFileContent::Status;
  const TrustedFileContent policy =
      Security::read_trusted_file(file, kMaxFileBytes);
  switch (policy.status) {
  case Status::ok:
    break;
  case Status::absent:
    return {std::errc{}, "ok", {}}; // no policy file: no signature required
  case Status::cannot_inspect:
    return {std::errc::io_error, "cannot inspect Docker signer policy", {}};
  case Status::untrusted:
    return {std::errc::io_error, "Docker signer policy is not root-owned", {}};
  case Status::cannot_open:
    return {std::errc::io_error, "cannot open Docker signer policy", {}};
  case Status::cannot_read:
    return {std::errc::io_error, "cannot read Docker signer policy", {}};
  case Status::too_large:
    return {std::errc::io_error, "Docker signer policy is too large", {}};
  }

  const auto entries = parse(policy.data);
  if (!entries) {
    return {std::errc::io_error, "Docker signer policy is malformed", {}};
  }
  return find(*entries, server);
}

} // namespace methuselah
