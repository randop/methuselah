#include "methuselah/docker_credentials.hpp"

#include "methuselah/text_util.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <iterator>
#include <string>
#include <string_view>
#include <utility>

#include <arpa/inet.h>

namespace methuselah {
namespace {

// "DOCKER_USER-NAME" -> "username".
std::string normalize_key(std::string_view key) {
  std::string stripped;
  std::copy_if(key.begin(), key.end(), std::back_inserter(stripped),
               [](char c) { return c != '_' && c != '-'; });
  std::string out = strutil::ascii_lower(stripped);
  if (out.starts_with("docker")) {
    out.erase(0, 6);
  }
  return out;
}

// Map the accepted spellings onto the two fields we store.
std::string canonical_key(std::string_view key) {
  std::string normalized = normalize_key(key);
  if (normalized == "user" || normalized == "login" || normalized == "email") {
    return "username";
  }
  if (normalized == "secret" || normalized == "token" ||
      normalized == "identitytoken" || normalized == "identity") {
    return "password";
  }
  return normalized;
}

// One field of the credentials file. The array order is the order in which
// parse() reports problems.
struct FieldSpec {
  std::string_view key;
  std::size_t min_size = 0;
  std::size_t max_size = 0;
  std::string_view missing;
  std::string_view malformed;
};

enum Field : std::size_t { kUsername, kPassword };

constexpr std::array<FieldSpec, 2> kFields = {{
    {"username", 1, 256, "credentials file has no username",
     "username has an unexpected format"},
    {"password", 1, 4096, "credentials file has no password",
     "password has an unexpected format"},
}};

constexpr std::size_t kJsonOverhead = 512;

DockerParseResult invalid(std::string_view reason) {
  return {std::errc::invalid_argument, reason, {}};
}

// Values stay on one line and may contain printable ASCII, tabs, and valid
// UTF-8. Inspect the bytes in place without copying the credential.
bool valid_value(std::string_view value, const FieldSpec &spec) {
  if (value.size() < spec.min_size || value.size() > spec.max_size) {
    return false;
  }
  for (std::size_t i = 0; i < value.size();) {
    const auto lead = static_cast<unsigned char>(value[i++]);
    if (lead < 0x80) {
      if (lead != '\t' && (lead < 0x20 || lead == 0x7f)) {
        return false;
      }
      continue;
    }
    if (lead < 0xc2 || lead > 0xf4) {
      return false;
    }
    const std::size_t length = lead < 0xe0 ? 1 : lead < 0xf0 ? 2 : 3;
    if (value.size() - i < length) {
      return false;
    }
    // Restrict the first continuation byte to exclude overlong encodings,
    // surrogates, and code points above U+10FFFF.
    const unsigned char min = lead == 0xe0 ? 0xa0 : lead == 0xf0 ? 0x90 : 0x80;
    const unsigned char max = lead == 0xed ? 0x9f : lead == 0xf4 ? 0x8f : 0xbf;
    const auto first = static_cast<unsigned char>(value[i++]);
    if (first < min || first > max) {
      return false;
    }
    for (std::size_t j = 1; j < length; ++j) {
      const auto byte = static_cast<unsigned char>(value[i++]);
      if (byte < 0x80 || byte > 0xbf) {
        return false;
      }
    }
  }
  return true;
}

void append_json_string(SecureString &out, std::string_view value) {
  constexpr char kHex[] = "0123456789abcdef";
  out.push_back('"');
  for (const unsigned char c : value) {
    switch (c) {
    case '"':
      out.append("\\\"");
      break;
    case '\\':
      out.append("\\\\");
      break;
    case '\b':
      out.append("\\b");
      break;
    case '\f':
      out.append("\\f");
      break;
    case '\n':
      out.append("\\n");
      break;
    case '\r':
      out.append("\\r");
      break;
    case '\t':
      out.append("\\t");
      break;
    default:
      if (c < 0x20) {
        out.append("\\u00");
        out.push_back(kHex[c >> 4]);
        out.push_back(kHex[c & 0x0f]);
      } else {
        out.push_back(static_cast<char>(c));
      }
      break;
    }
  }
  out.push_back('"');
}

std::string_view strip_scheme(std::string_view server) {
  constexpr std::string_view kHttps = "https://";
  constexpr std::string_view kHttp = "http://";
  if (server.starts_with(kHttps)) {
    server.remove_prefix(kHttps.size());
  } else if (server.starts_with(kHttp)) {
    server.remove_prefix(kHttp.size());
  }
  return server;
}

std::string_view strip_trailing_slash(std::string_view server) {
  while (!server.empty() && server.back() == '/') {
    server.remove_suffix(1);
  }
  return server;
}

} // namespace

DockerParseResult DockerCredentials::parse(std::string_view text) {
  DockerCredentials creds;
  // Parsed straight into the wiped-on-destruction members, so no secret is
  // ever copied into temporary storage that would outlive an error return.
  const std::array<SecureString *, kFields.size()> slots = {&creds.username_,
                                                            &creds.secret_};
  std::array<bool, kFields.size()> seen{};

  while (!text.empty()) {
    const std::string_view line = strutil::trim(strutil::next_line(text));
    if (line.empty() || line.front() == '#') {
      continue;
    }

    const auto eq = line.find('=');
    if (eq == std::string_view::npos) {
      return invalid("malformed line in credentials file (expected key=value)");
    }
    const std::string key = canonical_key(strutil::trim(line.substr(0, eq)));
    const std::string_view value = strutil::trim(line.substr(eq + 1));

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

  for (std::size_t i = 0; i < kFields.size(); ++i) {
    if (slots[i]->empty()) {
      return invalid(kFields[i].missing);
    }
  }
  for (std::size_t i = 0; i < kFields.size(); ++i) {
    if (!valid_value(*slots[i], kFields[i])) {
      return invalid(kFields[i].malformed);
    }
  }

  return {std::errc{}, "ok", std::move(creds)};
}

SecureString DockerCredentials::to_credential_helper_json(
    std::string_view server_url) const {
  SecureString out;
  secure_reserve(out, kJsonOverhead + server_url.size() * 2 + username_.size() +
                          secret_.size() * 2);
  out.append("{\"ServerURL\":");
  append_json_string(out, server_url);
  out.append(",\"Username\":");
  append_json_string(out, username_);
  out.append(",\"Secret\":");
  append_json_string(out, secret_);
  out.append("}\n");
  return out;
}

bool valid_docker_server(std::string_view server) {
  if (server.empty() || server.size() > 2048) {
    return false;
  }
  if (!std::all_of(server.begin(), server.end(), [](unsigned char c) {
        return c > 0x20 && c < 0x7f && c != '"' && c != '\\' && c != '#' &&
               c != ';';
      })) {
    return false;
  }

  const auto bracket = server.find_first_of("[]");
  if (bracket == std::string_view::npos) {
    return true;
  }
  const auto address = strip_scheme(server);
  const auto host = address.substr(0, address.find('/'));
  const auto close = host.find(']');
  if (!host.starts_with('[') || close == std::string_view::npos ||
      address.find_first_of("[]", close + 1) != std::string_view::npos) {
    return false;
  }
  const std::string literal(host.substr(1, close - 1));
  struct in6_addr ipv6{};
  if (::inet_pton(AF_INET6, literal.c_str(), &ipv6) != 1) {
    return false;
  }
  const auto port = host.substr(close + 1);
  return port.empty() || (port.starts_with(':') && port.size() > 1 &&
                          std::all_of(port.begin() + 1, port.end(), [](char c) {
                            return c >= '0' && c <= '9';
                          }));
}

std::vector<std::string> docker_server_aliases(std::string_view server) {
  std::vector<std::string> aliases;
  const auto add = [&aliases](std::string_view value) {
    if (value.empty()) {
      return;
    }
    if (std::find(aliases.begin(), aliases.end(), value) == aliases.end()) {
      aliases.emplace_back(value);
    }
  };

  add(server);
  const std::string_view without_scheme = strip_scheme(server);
  add(without_scheme);
  add(strip_trailing_slash(server));
  add(strip_trailing_slash(without_scheme));

  const auto host = without_scheme.substr(0, without_scheme.find('/'));
  add(host);

  // Docker's default registry has been spelled several ways over time. Let a
  // single [docker:docker.io] section cover all of them.
  if (host == "index.docker.io" || host == "registry-1.docker.io" ||
      host == "docker.io") {
    add("docker.io");
    add("index.docker.io");
    add("registry-1.docker.io");
  }

  return aliases;
}

std::vector<std::string> docker_config_sections(std::string_view server) {
  std::vector<std::string> sections;
  for (const auto &alias : docker_server_aliases(server)) {
    if (alias.find('[') == std::string::npos) {
      sections.push_back("docker:" + alias);
      continue;
    }
    // Use a separate prefix so existing literal percent escapes in docker:
    // sections cannot collide with encoded IPv6 addresses.
    std::string section = "docker-ipv6:";
    for (const char c : alias) {
      switch (c) {
      case '[':
        section.append("%5B");
        break;
      case ']':
        section.append("%5D");
        break;
      case '%':
        section.append("%25");
        break;
      default:
        section.push_back(c);
      }
    }
    sections.push_back(std::move(section));
  }
  return sections;
}

} // namespace methuselah
