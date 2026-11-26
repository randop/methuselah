#include "methuselah/aws_credentials.hpp"

#include "methuselah/text_util.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <ctime>
#include <iterator>
#include <numeric>
#include <optional>
#include <utility>

#include <time.h>

namespace methuselah {
namespace {

// "AWS_Access-Key_ID" -> "accesskeyid".
std::string normalize_key(std::string_view key) {
  std::string stripped;
  std::copy_if(key.begin(), key.end(), std::back_inserter(stripped),
               [](char c) { return c != '_' && c != '-'; });
  std::string out = strutil::ascii_lower(stripped);
  if (out.starts_with("aws")) {
    out.erase(0, 3);
  }
  return out;
}

bool all_of_set(std::string_view value, std::string_view allowed) {
  return std::all_of(value.begin(), value.end(), [&](char c) {
    return allowed.find(c) != std::string_view::npos;
  });
}

// botocore refreshes temporary credentials once fewer than about 15 minutes
// remain, so a shorter lifetime would make the CLI call this helper (and the
// passphrase prompt) again for every request.
constexpr std::time_t kMinRemainingSeconds = 15 * 60;

constexpr std::string_view kUpperAlnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
constexpr std::string_view kBase64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
constexpr std::string_view kToken =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-.";

// One secret field of the credentials file. The array order is the order of
// AwsCredentials::parse's `slots`, and validation reports problems in this
// order too.
struct FieldSpec {
  std::string_view key; // normalised, see normalize_key()
  std::string_view charset;
  std::size_t min_size = 0;
  std::size_t max_size = 0;
  std::string_view missing;   // reason when absent or empty; empty: optional
  std::string_view malformed; // reason when the value has the wrong shape
};

enum Field : std::size_t { kAccessKeyId, kSecretAccessKey, kSessionToken };

constexpr std::array<FieldSpec, 3> kFields = {{
    {"accesskeyid", kUpperAlnum, 16, 128,
     "credentials file has no access_key_id",
     "access_key_id has an unexpected format"},
    {"secretaccesskey", kBase64, 20, 128,
     "credentials file has no secret_access_key",
     "secret_access_key has an unexpected format"},
    {"sessiontoken",
     kToken,
     16,
     4096,
     {},
     "session_token has an unexpected format"},
}};

constexpr std::size_t kJsonOverhead = 512;

AwsParseResult invalid(std::string_view reason) {
  return {std::errc::invalid_argument, reason, {}};
}

// Strict "YYYY-MM-DDTHH:MM:SSZ". Returns the instant as UTC epoch seconds.
std::optional<std::time_t> parse_expiration(std::string_view value) {
  constexpr std::string_view syntax = "dddd-dd-ddTdd:dd:ddZ";
  if (value.size() != syntax.size()) {
    return std::nullopt;
  }
  for (std::size_t i = 0; i < syntax.size(); ++i) {
    if (syntax[i] == 'd' ? value[i] < '0' || value[i] > '9'
                         : value[i] != syntax[i]) {
      return std::nullopt;
    }
  }
  const auto number = [&](std::size_t pos, std::size_t length) {
    const std::string_view digits = value.substr(pos, length);
    return std::accumulate(digits.begin(), digits.end(), 0,
                           [](int n, char c) { return n * 10 + (c - '0'); });
  };
  struct tm parts{};
  parts.tm_year = number(0, 4) - 1900;
  parts.tm_mon = number(5, 2) - 1;
  parts.tm_mday = number(8, 2);
  parts.tm_hour = number(11, 2);
  parts.tm_min = number(14, 2);
  parts.tm_sec = number(17, 2);

  // timegm() normalises out-of-range fields (month 13, 30 February, second 60)
  // instead of failing, so reject anything it had to change.
  const auto requested = parts;
  errno = 0;
  const auto epoch = ::timegm(&parts);
  if (errno == EOVERFLOW || parts.tm_year != requested.tm_year ||
      parts.tm_mon != requested.tm_mon || parts.tm_mday != requested.tm_mday ||
      parts.tm_hour != requested.tm_hour || parts.tm_min != requested.tm_min ||
      parts.tm_sec != requested.tm_sec) {
    return std::nullopt;
  }
  return epoch;
}

using FieldSlots = std::array<SecureString *, kFields.size()>;

// Why the secret fields are unusable, or an empty view when they are fine.
// Problems are reported in table order: everything required first, then the
// shape of each field that is present.
std::string_view field_problem(const FieldSlots &slots,
                               const std::array<bool, kFields.size()> &seen) {
  for (std::size_t i = 0; i < kFields.size(); ++i) {
    if (!kFields[i].missing.empty() && slots[i]->empty()) {
      return kFields[i].missing;
    }
  }
  for (std::size_t i = 0; i < kFields.size(); ++i) {
    const std::string_view value = *slots[i];
    const FieldSpec &spec = kFields[i];
    if (seen[i] &&
        (value.size() < spec.min_size || value.size() > spec.max_size ||
         !all_of_set(value, spec.charset))) {
      return spec.malformed;
    }
  }
  return {};
}

// Why the expiration is unusable, or an empty view when it is fine.
std::string_view expiry_problem(std::string_view expiration, bool have_expiry,
                                bool have_token, std::time_t now) {
  if (!have_expiry) {
    // Temporary credentials with no expiry would be cached by the CLI
    // forever; refuse rather than hand out something that never refreshes.
    return have_token
               ? "temporary credentials (session_token) require an expiration"
               : std::string_view{};
  }
  const auto expiry = parse_expiration(expiration);
  if (!expiry) {
    return "expiration must look like YYYY-MM-DDTHH:MM:SSZ (UTC)";
  }
  if (*expiry <= now) {
    return "credentials have expired";
  }
  if (*expiry - now <= kMinRemainingSeconds) {
    return "credentials expire in 15 minutes or less; refresh them";
  }
  return {};
}

} // namespace

AwsParseResult AwsCredentials::parse(std::string_view text, std::time_t now) {
  AwsCredentials creds;
  // Parsed straight into the wiped-on-destruction members, so no secret is
  // ever copied into temporary storage that would outlive an error return.
  const FieldSlots slots = {&creds.access_key_id_, &creds.secret_access_key_,
                            &creds.session_token_};
  std::array<bool, kFields.size()> seen{};
  bool have_expiry = false;

  while (!text.empty()) {
    const std::string_view line = strutil::trim(strutil::next_line(text));
    if (line.empty() || line.front() == '#') {
      continue;
    }

    const auto eq = line.find('=');
    if (eq == std::string_view::npos) {
      return invalid("malformed line in credentials file (expected key=value)");
    }
    const std::string key = normalize_key(strutil::trim(line.substr(0, eq)));
    const std::string_view value = strutil::trim(line.substr(eq + 1));

    if (key == "expiration") {
      if (have_expiry) {
        return invalid("duplicate expiration in credentials file");
      }
      have_expiry = true;
      creds.expiration_.assign(value);
      continue;
    }

    const auto field =
        std::find_if(kFields.begin(), kFields.end(),
                     [&](const FieldSpec &f) { return f.key == key; });
    if (field == kFields.end()) {
      return invalid("unknown key in credentials file");
    }
    const auto index = static_cast<std::size_t>(field - kFields.begin());
    if (seen[index]) {
      return invalid("duplicate key in credentials file");
    }
    seen[index] = true;
    secure_reserve(*slots[index], value.size());
    slots[index]->assign(value.data(), value.size());
  }

  if (const auto problem = field_problem(slots, seen); !problem.empty()) {
    return invalid(problem);
  }
  if (const auto problem = expiry_problem(creds.expiration_, have_expiry,
                                          seen[kSessionToken], now);
      !problem.empty()) {
    return invalid(problem);
  }

  return {std::errc{}, "ok", std::move(creds)};
}

SecureString AwsCredentials::to_credential_process_json() const {
  // Every field was validated against a character set containing no quote,
  // backslash, or control character, so no JSON escaping is needed.
  SecureString out;
  secure_reserve(out, kJsonOverhead + session_token_.size());
  out.append("{\"Version\":1,\"AccessKeyId\":\"").append(access_key_id_);
  out.append("\",\"SecretAccessKey\":\"").append(secret_access_key_);
  out.push_back('"');
  if (!session_token_.empty()) {
    out.append(",\"SessionToken\":\"").append(session_token_);
    out.push_back('"');
  }
  if (!expiration_.empty()) {
    out.append(",\"Expiration\":\"").append(expiration_);
    out.push_back('"');
  }
  out.append("}\n");
  return out;
}

} // namespace methuselah
