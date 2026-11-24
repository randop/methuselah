#include "methuselah/aws_signers.hpp"

#include "methuselah/security.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace methuselah {
namespace {

constexpr std::size_t kMaxFileBytes = 1U << 16;

bool is_fingerprint(std::string_view text) {
  return (text.size() == 40 || text.size() == 64) &&
         std::all_of(text.begin(), text.end(),
                     [](unsigned char c) { return std::isxdigit(c) != 0; });
}

std::string upper(std::string_view text) {
  std::string out(text.size(), '\0');
  for (std::size_t i = 0; i < text.size(); ++i) {
    out[i] =
        static_cast<char>(std::toupper(static_cast<unsigned char>(text[i])));
  }
  return out;
}

std::string_view trim(std::string_view line) {
  while (!line.empty() &&
         std::isspace(static_cast<unsigned char>(line.front())) != 0) {
    line.remove_prefix(1);
  }
  while (!line.empty() &&
         std::isspace(static_cast<unsigned char>(line.back())) != 0) {
    line.remove_suffix(1);
  }
  return line;
}

} // namespace

std::filesystem::path AwsSigners::default_file() {
  return "/etc/methuselah/aws-signers";
}

std::optional<AwsSigners::Entries> AwsSigners::parse(std::string_view text) {
  Entries entries;
  while (!text.empty()) {
    const auto nl = text.find('\n');
    const std::string_view line = trim(text.substr(0, nl));
    text =
        nl == std::string_view::npos ? std::string_view{} : text.substr(nl + 1);
    if (line.empty() || line.front() == '#') {
      continue;
    }
    const auto space = line.find_first_of(" \t");
    if (space == std::string_view::npos) {
      return std::nullopt;
    }
    const std::string_view profile = line.substr(0, space);
    const std::string_view fingerprint = trim(line.substr(space));
    if (!is_fingerprint(fingerprint)) {
      return std::nullopt;
    }
    const bool duplicate =
        std::any_of(entries.begin(), entries.end(),
                    [&](const auto &entry) { return entry.first == profile; });
    if (duplicate) {
      return std::nullopt;
    }
    entries.emplace_back(std::string(profile), upper(fingerprint));
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
  struct stat link{};
  if (::lstat(file.c_str(), &link) != 0) {
    if (errno == ENOENT) {
      return {std::errc{}, "ok", {}};
    }
    return {std::errc::io_error, "cannot inspect AWS signer policy", {}};
  }
  const auto trusted = Security::trusted_file(file);
  if (!trusted) {
    return {std::errc::io_error, "AWS signer policy is not root-owned", {}};
  }
  const int fd = ::open(trusted->c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    return {std::errc::io_error, "cannot open AWS signer policy", {}};
  }
  // The path was vetted above; vet what was actually opened as well.
  struct stat info{};
  if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != 0 ||
      (info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
    ::close(fd);
    return {std::errc::io_error, "AWS signer policy is not root-owned", {}};
  }
  std::string text;
  char buffer[1024];
  ssize_t n = 0;
  for (;;) {
    n = ::read(fd, buffer, sizeof(buffer));
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0 || static_cast<std::size_t>(n) > kMaxFileBytes - text.size()) {
      break;
    }
    text.append(buffer, static_cast<std::size_t>(n));
  }
  ::close(fd);
  if (n < 0) {
    return {std::errc::io_error, "cannot read AWS signer policy", {}};
  }
  if (n > 0) {
    return {std::errc::io_error, "AWS signer policy is too large", {}};
  }
  const auto entries = parse(text);
  if (!entries) {
    return {std::errc::io_error, "AWS signer policy is malformed", {}};
  }
  return find(*entries, profile);
}

} // namespace methuselah
