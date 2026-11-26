#include "methuselah/aws_signers.hpp"

#include "methuselah/security.hpp"
#include "methuselah/text_util.hpp"

#include <algorithm>
#include <cctype>

namespace methuselah {
namespace {

constexpr std::size_t kMaxFileBytes = 1U << 16;
constexpr std::size_t kMaxProfileNameLength = 64;
// OpenPGP fingerprints: 40 hex digits (SHA-1, v4 keys) or 64 (SHA-256, v5/v6).
constexpr std::size_t kSha1FingerprintLength = 40;
constexpr std::size_t kSha256FingerprintLength = 64;

bool is_fingerprint(std::string_view text) {
  return (text.size() == kSha1FingerprintLength ||
          text.size() == kSha256FingerprintLength) &&
         strutil::is_hex(text);
}

} // namespace

std::filesystem::path AwsSigners::default_file() {
  return "/etc/methuselah/aws-signers";
}

bool AwsSigners::valid_profile_name(std::string_view name) {
  return !name.empty() && name.size() <= kMaxProfileNameLength &&
         std::all_of(name.begin(), name.end(), [](unsigned char c) {
           return std::isalnum(c) != 0 || c == '_' || c == '-' || c == '.' ||
                  c == '@';
         });
}

std::optional<AwsSigners::Entries> AwsSigners::parse(std::string_view text) {
  Entries entries;
  while (!text.empty()) {
    const std::string_view line = strutil::trim(strutil::next_line(text));
    if (line.empty() || line.front() == '#') {
      continue;
    }
    const auto space = line.find_first_of(" \t");
    if (space == std::string_view::npos) {
      return std::nullopt;
    }
    const std::string_view profile = line.substr(0, space);
    const std::string_view fingerprint = strutil::trim(line.substr(space));
    if (!valid_profile_name(profile) || !is_fingerprint(fingerprint)) {
      return std::nullopt;
    }
    const bool duplicate =
        std::any_of(entries.begin(), entries.end(),
                    [&](const auto &entry) { return entry.first == profile; });
    if (duplicate) {
      return std::nullopt;
    }
    entries.emplace_back(std::string(profile),
                         strutil::ascii_upper(fingerprint));
  }
  return entries;
}

AwsSigners::Lookup AwsSigners::find(const Entries &entries,
                                    std::string_view profile) {
  for (const auto &[name, fingerprint] : entries) {
    if (name == profile) {
      return {std::errc{}, "ok", fingerprint};
    }
  }
  return {std::errc{}, "ok", {}};
}

AwsSigners::Lookup AwsSigners::load(const std::filesystem::path &file,
                                    std::string_view profile) {
  using Status = TrustedFileContent::Status;
  const TrustedFileContent policy =
      Security::read_trusted_file(file, kMaxFileBytes);
  switch (policy.status) {
  case Status::ok:
    break;
  case Status::absent:
    return {std::errc{}, "ok", {}}; // no policy file: no signature required
  case Status::cannot_inspect:
    return {std::errc::io_error, "cannot inspect AWS signer policy", {}};
  case Status::untrusted:
    return {std::errc::io_error, "AWS signer policy is not root-owned", {}};
  case Status::cannot_open:
    return {std::errc::io_error, "cannot open AWS signer policy", {}};
  case Status::cannot_read:
    return {std::errc::io_error, "cannot read AWS signer policy", {}};
  case Status::too_large:
    return {std::errc::io_error, "AWS signer policy is too large", {}};
  }

  const auto entries = parse(policy.data);
  if (!entries) {
    return {std::errc::io_error, "AWS signer policy is malformed", {}};
  }
  return find(*entries, profile);
}

} // namespace methuselah
