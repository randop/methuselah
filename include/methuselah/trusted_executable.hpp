#pragma once

#include <filesystem>
#include <optional>
#include <sys/stat.h>
#include <unistd.h>

namespace methuselah::detail {

// Trust only root-owned installations without group/other write access.
// Inspect every traversed component, including symlink targets before any '..'
// components are collapsed. Canonicalization alone would hide those components.
inline std::optional<std::filesystem::path>
trustedExecutable(const std::filesystem::path &candidate) {
  if (!candidate.is_absolute()) {
    return std::nullopt;
  }

  std::filesystem::path resolved = "/";
  auto remaining = candidate.relative_path();
  unsigned links = 0;
  struct stat info {};
  if (::lstat("/", &info) != 0 || info.st_uid != 0 ||
      (info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
    return std::nullopt;
  }

  while (!remaining.empty()) {
    const auto component = *remaining.begin();
    std::filesystem::path tail;
    auto it = remaining.begin();
    for (++it; it != remaining.end(); ++it) {
      tail /= *it;
    }
    remaining = tail;
    if (component == ".") {
      continue;
    }
    if (component == "..") {
      resolved = resolved.parent_path();
      continue;
    }

    const auto next = resolved / component;
    if (::lstat(next.c_str(), &info) != 0 || info.st_uid != 0) {
      return std::nullopt;
    }
    if (S_ISLNK(info.st_mode)) {
      if (++links > 40) {
        return std::nullopt;
      }
      std::error_code ec;
      const auto target = std::filesystem::read_symlink(next, ec);
      if (ec) {
        return std::nullopt;
      }
      if (target.is_absolute()) {
        resolved = "/";
      }
      remaining = remaining.empty() ? target.relative_path()
                                    : target.relative_path() / remaining;
      continue;
    }
    if ((info.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        (!remaining.empty() && !S_ISDIR(info.st_mode))) {
      return std::nullopt;
    }
    resolved = next;
  }

  if (::stat(resolved.c_str(), &info) != 0 || !S_ISREG(info.st_mode) ||
      ::access(resolved.c_str(), X_OK) != 0) {
    return std::nullopt;
  }
  return resolved;
}

} // namespace methuselah::detail
