#include "methuselah/aws_credentials.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstddef>
#include <ctime>
#include <optional>
#include <utility>

#include <time.h>

namespace methuselah {
namespace {

std::string_view trim(std::string_view value) {
  while (!value.empty() &&
         std::isspace(static_cast<unsigned char>(value.front())) != 0) {
    value.remove_prefix(1);
  }
  while (!value.empty() &&
         std::isspace(static_cast<unsigned char>(value.back())) != 0) {
    value.remove_suffix(1);
  }
  return value;
}

// "AWS_Access-Key_ID" -> "accesskeyid".
std::string normalize_key(std::string_view key) {
  std::string out;
  for (const char raw : key) {
    const auto c = static_cast<unsigned char>(raw);
    if (c == '_' || c == '-') {
      continue;
    }
    out.push_back(static_cast<char>(std::tolower(c)));
  }
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

constexpr std::string_view kUpperAlnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
constexpr std::string_view kBase64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
constexpr std::string_view kToken =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-.";

// Strict "YYYY-MM-DDTHH:MM:SSZ". Returns the instant as UTC epoch seconds.
std::optional<std::time_t> parse_expiration(const std::string &value) {
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
  struct tm parts{};
  const char *end = ::strptime(value.c_str(), "%Y-%m-%dT%H:%M:%SZ", &parts);
  if (end != value.data() + value.size()) {
    return std::nullopt;
  }
  const auto parsed = parts;
  errno = 0;
  const auto epoch = ::timegm(&parts);
  if (errno == EOVERFLOW || parts.tm_year != parsed.tm_year ||
      parts.tm_mon != parsed.tm_mon || parts.tm_mday != parsed.tm_mday ||
      parts.tm_hour != parsed.tm_hour || parts.tm_min != parsed.tm_min ||
      parts.tm_sec != parsed.tm_sec) {
    return std::nullopt;
  }
  return epoch;
}

} // namespace

AwsParseResult AwsCredentials::parse(std::string_view text, std::time_t now) {
  AwsCredentials creds;
  bool haveAccess = false;
  bool haveSecret = false;
  bool haveToken = false;
  bool haveExpiry = false;

  while (!text.empty()) {
    const auto nl = text.find('\n');
    std::string_view line = trim(text.substr(0, nl));
    text =
        nl == std::string_view::npos ? std::string_view{} : text.substr(nl + 1);
    if (line.empty() || line.front() == '#') {
      continue;
    }

    const auto eq = line.find('=');
    if (eq == std::string_view::npos) {
      return {std::errc::invalid_argument,
              "malformed line in credentials file (expected key=value)",
              {}};
    }
    const std::string key = normalize_key(trim(line.substr(0, eq)));
    const std::string_view value = trim(line.substr(eq + 1));

    auto assign = [&](SecureString &target, bool &seen) {
      if (seen) {
        return false;
      }
      seen = true;
      secure_reserve(target, value.size());
      target.assign(value.data(), value.size());
      return true;
    };

    if (key == "accesskeyid") {
      if (!assign(creds.access_key_id_, haveAccess)) {
        return {std::errc::invalid_argument,
                "duplicate key in credentials file",
                {}};
      }
    } else if (key == "secretaccesskey") {
      if (!assign(creds.secret_access_key_, haveSecret)) {
        return {std::errc::invalid_argument,
                "duplicate key in credentials file",
                {}};
      }
    } else if (key == "sessiontoken") {
      if (!assign(creds.session_token_, haveToken)) {
        return {std::errc::invalid_argument,
                "duplicate key in credentials file",
                {}};
      }
    } else if (key == "expiration") {
      if (haveExpiry) {
        return {std::errc::invalid_argument,
                "duplicate expiration in credentials file",
                {}};
      }
      haveExpiry = true;
      creds.expiration_.assign(value);
    } else {
      return {
          std::errc::invalid_argument, "unknown key in credentials file", {}};
    }
  }

  if (!haveAccess || creds.access_key_id_.empty()) {
    return {std::errc::invalid_argument,
            "credentials file has no access_key_id",
            {}};
  }
  if (!haveSecret || creds.secret_access_key_.empty()) {
    return {std::errc::invalid_argument,
            "credentials file has no secret_access_key",
            {}};
  }

  const std::string_view access = creds.access_key_id_;
  if (access.size() < 16 || access.size() > 128 ||
      !all_of_set(access, kUpperAlnum)) {
    return {std::errc::invalid_argument,
            "access_key_id has an unexpected format",
            {}};
  }
  const std::string_view secret = creds.secret_access_key_;
  if (secret.size() < 20 || secret.size() > 128 ||
      !all_of_set(secret, kBase64)) {
    return {std::errc::invalid_argument,
            "secret_access_key has an unexpected format",
            {}};
  }
  if (haveToken) {
    const std::string_view token = creds.session_token_;
    if (token.size() < 16 || token.size() > 4096 ||
        !all_of_set(token, kToken)) {
      return {std::errc::invalid_argument,
              "session_token has an unexpected format",
              {}};
    }
  }
  if (haveExpiry) {
    const auto expiry = parse_expiration(creds.expiration_);
    if (!expiry) {
      return {std::errc::invalid_argument,
              "expiration must look like YYYY-MM-DDTHH:MM:SSZ (UTC)",
              {}};
    }
    if (*expiry <= now) {
      return {std::errc::invalid_argument, "credentials have expired", {}};
    }
  } else if (haveToken) {
    // Temporary credentials with no expiry would be cached by the CLI
    // forever; refuse rather than hand out something that never refreshes.
    return {std::errc::invalid_argument,
            "temporary credentials (session_token) require an expiration",
            {}};
  }

  return {std::errc{}, "ok", std::move(creds)};
}

SecureString AwsCredentials::to_credential_process_json() const {
  // Every field was validated against a character set containing no quote,
  // backslash, or control character, so no JSON escaping is needed.
  SecureString out;
  secure_reserve(out, 512 + session_token_.size());
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
