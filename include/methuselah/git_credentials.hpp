#pragma once

#include "methuselah/secure_memory.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace methuselah {

class GitPredicate {
public:
  [[nodiscard]] static GitPredicate parse(std::string_view input);
  [[nodiscard]] static GitPredicate read_from_stdin();

  GitPredicate() = default;
  GitPredicate(const GitPredicate &) = default;
  GitPredicate &operator=(const GitPredicate &) = default;
  GitPredicate(GitPredicate &&) noexcept = default;
  GitPredicate &operator=(GitPredicate &&) noexcept = default;
  ~GitPredicate() { secure_clear(password_); }

  void write_credentials(std::string_view password) const;

  [[nodiscard]] bool has_capability(const std::string &cap) const;
  [[nodiscard]] bool has_wwwauth(const std::string &auth) const;

  [[nodiscard]] const std::string &protocol() const noexcept {
    return protocol_;
  }
  [[nodiscard]] const std::string &host() const noexcept { return host_; }
  [[nodiscard]] const std::string &username() const noexcept {
    return username_;
  }
  [[nodiscard]] const SecureString &password() const noexcept {
    return password_;
  }

private:
  std::vector<std::string> capabilities_;
  std::vector<std::string> wwwauth_;
  std::string protocol_;
  std::string host_;
  std::string username_;
  SecureString password_;
};

} // namespace methuselah
