#pragma once

#include "methuselah/secure_memory.hpp"

#include <ctime>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace methuselah {

struct AwsParseResult;

// Credentials in the format AWS CLI's `credential_process` expects.
//
// Stored (GPG-encrypted) as key=value lines. Both the short names and the
// ~/.aws/credentials names are accepted, case-insensitively:
//
//   access_key_id=AKIA...        (aws_access_key_id)       required
//   secret_access_key=...        (aws_secret_access_key)   required
//   session_token=...            (aws_session_token)       optional
//   expiration=2026-11-22T18:00:00Z                        optional
//
// Unknown keys, duplicates, and values outside the character sets AWS uses are
// rejected, so nothing in the payload can break out of the JSON document.
class AwsCredentials {
public:
  AwsCredentials() = default;
  ~AwsCredentials() { wipe(); }

  AwsCredentials(const AwsCredentials &) = delete;
  AwsCredentials &operator=(const AwsCredentials &) = delete;
  AwsCredentials(AwsCredentials &&other) noexcept
      : access_key_id_(std::move(other.access_key_id_)),
        secret_access_key_(std::move(other.secret_access_key_)),
        session_token_(std::move(other.session_token_)),
        expiration_(std::move(other.expiration_)) {
    other.wipe();
  }
  AwsCredentials &operator=(AwsCredentials &&other) noexcept {
    if (this != &other) {
      wipe();
      access_key_id_ = std::move(other.access_key_id_);
      secret_access_key_ = std::move(other.secret_access_key_);
      session_token_ = std::move(other.session_token_);
      expiration_ = std::move(other.expiration_);
      other.wipe();
    }
    return *this;
  }

  // Parses credentials and returns a result with a standard error condition,
  // a short reason, and the parsed credentials. On failure `credentials` is
  // empty. Credentials that have expired, or expire within 15 minutes of
  // `now` (the CLI would re-run the helper on every call), are refused.
  [[nodiscard]] static AwsParseResult
  parse(std::string_view text, std::time_t now = std::time(nullptr));

  // {"Version":1,"AccessKeyId":...} followed by a newline, in guarded memory.
  [[nodiscard]] SecureString to_credential_process_json() const;

  [[nodiscard]] bool has_session_token() const noexcept {
    return !session_token_.empty();
  }
  [[nodiscard]] const std::string &expiration() const noexcept {
    return expiration_;
  }

private:
  void wipe() noexcept {
    secure_clear(access_key_id_);
    secure_clear(secret_access_key_);
    secure_clear(session_token_);
  }

  SecureString access_key_id_;
  SecureString secret_access_key_;
  SecureString session_token_;
  std::string expiration_;
};

// Outcome of AwsCredentials::parse(): a standard error condition plus a short
// reason, mirroring SecurityVerdict, together with the parsed credentials.
// `reason` is a view and owns nothing, so it must outlive the result.
struct AwsParseResult {
  std::errc result = std::errc::io_error;
  std::string_view reason{};
  AwsCredentials credentials;
};

} // namespace methuselah
