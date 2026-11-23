#include "methuselah/git_credentials.hpp"

#include <algorithm>
#include <cstddef>
#include <iostream>
#include <string_view>
#include <utility>

#include <unistd.h>

namespace methuselah {

GitPredicate::GitPredicate(const GitPredicate &other)
    : capabilities_(other.capabilities_), wwwauth_(other.wwwauth_),
      protocol_(other.protocol_), host_(other.host_),
      username_(other.username_) {
  if (!other.password_.empty()) {
    secure_reserve(password_, other.password_.size());
    password_.assign(other.password_);
  }
}

GitPredicate &GitPredicate::operator=(const GitPredicate &other) {
  if (this != &other) {
    GitPredicate copy(other);
    secure_clear(password_);
    *this = std::move(copy);
  }
  return *this;
}

GitPredicate GitPredicate::parse(std::string_view input) {
  GitPredicate predicate;

  // Parse with string_views so the password never passes through an
  // unguarded temporary std::string (istringstream, map, substr copies).
  while (!input.empty()) {
    const std::size_t nl = input.find('\n');
    std::string_view line = input.substr(0, nl);
    input = (nl == std::string_view::npos) ? std::string_view{}
                                           : input.substr(nl + 1);
    if (!line.empty() && line.back() == '\r') {
      line.remove_suffix(1);
    }
    if (line.empty() || line.front() == '#') {
      continue;
    }

    const std::size_t eq_pos = line.find('=');
    if (eq_pos == std::string_view::npos) {
      continue;
    }

    const std::string_view key = line.substr(0, eq_pos);
    const std::string_view value = line.substr(eq_pos + 1);

    if (key == "capability[]") {
      predicate.capabilities_.emplace_back(value);
    } else if (key == "wwwauth[]") {
      predicate.wwwauth_.emplace_back(value);
    } else if (key == "protocol") {
      predicate.protocol_ = value;
    } else if (key == "host") {
      predicate.host_ = value;
    } else if (key == "username") {
      predicate.username_ = value;
    } else if (key == "password") {
      secure_reserve(predicate.password_);
      predicate.password_.assign(value.data(), value.size());
    }
  }

  return predicate;
}

GitPredicate GitPredicate::read_from_stdin() {
  SecureString inputs;
  secure_reserve(inputs, 4096);
  std::string line;

  while (std::getline(std::cin, line)) {
    if (line.empty()) {
      break;
    }
    if (!inputs.empty()) {
      inputs.push_back('\n');
    }
    inputs.append(line);
    // The line may hold a password: wipe the unguarded copy immediately.
    secure_clear(line);
  }

  GitPredicate predicate = parse(inputs);
  secure_clear(inputs);
  return predicate;
}

void GitPredicate::write_credentials(std::string_view password) const {
  // Build in guarded memory and write via fd 1 directly: std::cout would keep
  // an unzeroed copy of the password in its internal buffer.
  SecureString out;
  secure_reserve(out, 512 + password.size());
  out.append("protocol=").append(protocol_);
  out.append("\nhost=").append(host_);
  out.append("\nusername=").append(username_);
  out.append("\npassword=").append(password);
  out.push_back('\n');
  std::cout.flush();
  (void)secure_write(STDOUT_FILENO, out);
  secure_clear(out);
}

bool GitPredicate::has_capability(const std::string &cap) const {
  return std::find(capabilities_.begin(), capabilities_.end(), cap) !=
         capabilities_.end();
}

bool GitPredicate::has_wwwauth(const std::string &auth) const {
  return std::find(wwwauth_.begin(), wwwauth_.end(), auth) != wwwauth_.end();
}

} // namespace methuselah
