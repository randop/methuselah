#include "methuselah/aws_credentials.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <ctime>

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
  if (value.size() != 20 || value.back() != 'Z') {
    return std::nullopt;
  }
  struct tm parts{};
  const char *end = ::strptime(value.c_str(), "%Y-%m-%dT%H:%M:%SZ", &parts);
  if (end == nullptr || *end != '\0') {
    return std::nullopt;
  }
  return ::timegm(&parts);
}

} // namespace

std::optional<AwsCredentials> AwsCredentials::parse(std::string_view text,
                                                    std::string &error,
                                                    std::time_t now) {
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
      error = "malformed line in credentials file (expected key=value)";
      return std::nullopt;
    }
    const std::string key = normalize_key(trim(line.substr(0, eq)));
    const std::string_view value = trim(line.substr(eq + 1));

    auto assign = [&](SecureString &target, bool &seen) {
      if (seen) {
        error = "duplicate key '" + key + "' in credentials file";
        return false;
      }
      seen = true;
      secure_reserve(target, value.size());
      target.assign(value.data(), value.size());
      return true;
    };

    if (key == "accesskeyid") {
      if (!assign(creds.access_key_id_, haveAccess)) {
        return std::nullopt;
      }
    } else if (key == "secretaccesskey") {
      if (!assign(creds.secret_access_key_, haveSecret)) {
        return std::nullopt;
      }
    } else if (key == "sessiontoken") {
      if (!assign(creds.session_token_, haveToken)) {
        return std::nullopt;
      }
    } else if (key == "expiration") {
      if (haveExpiry) {
        error = "duplicate key 'expiration' in credentials file";
        return std::nullopt;
      }
      haveExpiry = true;
      creds.expiration_.assign(value);
    } else {
      error = "unknown key '" + key + "' in credentials file";
      return std::nullopt;
    }
  }

  if (!haveAccess || creds.access_key_id_.empty()) {
    error = "credentials file has no access_key_id";
    return std::nullopt;
  }
  if (!haveSecret || creds.secret_access_key_.empty()) {
    error = "credentials file has no secret_access_key";
    return std::nullopt;
  }

  const std::string_view access = creds.access_key_id_;
  if (access.size() < 16 || access.size() > 128 ||
      !all_of_set(access, kUpperAlnum)) {
    error = "access_key_id has an unexpected format";
    return std::nullopt;
  }
  const std::string_view secret = creds.secret_access_key_;
  if (secret.size() < 20 || secret.size() > 128 ||
      !all_of_set(secret, kBase64)) {
    error = "secret_access_key has an unexpected format";
    return std::nullopt;
  }
  if (haveToken) {
    const std::string_view token = creds.session_token_;
    if (token.size() < 16 || token.size() > 4096 ||
        !all_of_set(token, kToken)) {
      error = "session_token has an unexpected format";
      return std::nullopt;
    }
  }
  if (haveExpiry) {
    const auto expiry = parse_expiration(creds.expiration_);
    if (!expiry) {
      error = "expiration must look like 2026-11-22T18:00:00Z (UTC)";
      return std::nullopt;
    }
    if (*expiry <= now) {
      error = "credentials expired at " + creds.expiration_;
      return std::nullopt;
    }
  } else if (haveToken) {
    // Temporary credentials with no expiry would be cached by the CLI
    // forever; refuse rather than hand out something that never refreshes.
    error = "temporary credentials (session_token) require an expiration";
    return std::nullopt;
  }

  return creds;
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
