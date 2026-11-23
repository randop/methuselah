#include "config.h"

#include "methuselah/aws_verifier.hpp"
#include "methuselah/git_helper.hpp"
#include "methuselah/process_info.hpp"
#include "methuselah/security.hpp"
#include "methuselah/ssh_helper.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>

#include <sys/stat.h>
#include <unistd.h>

namespace methuselah {

namespace {

void report(const ProcessInfo::Entry &e, const char *label) {
  std::cerr << label << ": pid " << e.pid << " (ppid " << e.ppid << ")\n"
            << "  exe:     " << e.exe << "\n"
            << "  cmdline: " << e.cmdline << "\n";
}

} // namespace

namespace {

enum class PathKind { file, executable, directory };

bool accepted_owner(const TrustPolicy &policy, uid_t owner) {
  return std::find(policy.owners.begin(), policy.owners.end(), owner) !=
         policy.owners.end();
}

std::optional<std::filesystem::path>
trusted_path(const std::filesystem::path &candidate, PathKind kind,
             const TrustPolicy &policy) {
  if (!candidate.is_absolute()) {
    return std::nullopt;
  }

  std::filesystem::path resolved = "/";
  auto remaining = candidate.relative_path();
  unsigned links = 0;
  struct stat info{};
  if (::lstat("/", &info) != 0 || !accepted_owner(policy, info.st_uid) ||
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
    if (::lstat(next.c_str(), &info) != 0 ||
        !accepted_owner(policy, info.st_uid)) {
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

  if (::stat(resolved.c_str(), &info) != 0 ||
      (kind == PathKind::directory ? !S_ISDIR(info.st_mode)
                                   : !S_ISREG(info.st_mode)) ||
      (kind == PathKind::executable && ::access(resolved.c_str(), X_OK) != 0)) {
    return std::nullopt;
  }
  return resolved;
}

} // namespace

std::optional<std::filesystem::path>
Security::trusted_executable(const std::filesystem::path &candidate,
                             const TrustPolicy &policy) {
  return trusted_path(candidate, PathKind::executable, policy);
}

std::optional<std::filesystem::path>
Security::trusted_file(const std::filesystem::path &candidate,
                       const TrustPolicy &policy) {
  return trusted_path(candidate, PathKind::file, policy);
}

std::optional<std::filesystem::path>
Security::trusted_directory(const std::filesystem::path &candidate,
                            const TrustPolicy &policy) {
  return trusted_path(candidate, PathKind::directory, policy);
}

SecurityVerdict Security::verify_git() const {
  const auto gitHttp = GitHelper::locateRemoteHttp();
  if (!gitHttp) {
    return {std::errc::io_error,
            "git-remote-http was not found in a trusted git installation"};
  }

  const auto caller = ProcessInfo::caller();
  if (!caller) {
    std::cerr << "caller: unavailable\n";
    return {std::errc::io_error, "caller process is unavailable"};
  }

  SPDLOG_TRACE("caller: {}", caller->exe);
  SPDLOG_TRACE("githttp: {}", gitHttp->string());

  if (caller->exe == "<unavailable>") {
    return {std::errc::io_error, "caller executable is unavailable"};
  }

  // Resolve both sides so symlinked install locations compare equal.
  std::error_code ec;
  const std::string callerExe =
      std::filesystem::weakly_canonical(caller->exe, ec).string();
  if (ec) {
    report(*caller, "caller");
    return {std::errc::io_error, "cannot resolve caller executable"};
  }

  const std::string helperExe =
      std::filesystem::weakly_canonical(*gitHttp, ec).string();
  if (ec) {
    return {std::errc::io_error, "cannot resolve git-remote-http"};
  }

  const bool same = std::filesystem::equivalent(callerExe, helperExe, ec);
  if (ec) {
    return {std::errc::io_error, "cannot compare caller with git-remote-http"};
  }
  if (same) {
    return {std::errc{}, "ok"};
  }
  return {std::errc::permission_denied, "caller is not git-remote-http"};
}

SecurityVerdict Security::verify_gpg() const {
  const auto caller = ProcessInfo::caller();
  if (!caller) {
    SPDLOG_TRACE("faulted: gpg no caller");
    return {std::errc::io_error, "caller process is unavailable"};
  }
  SPDLOG_TRACE("gpg caller cmdline: {}", caller->cmdline);

  const bool hasExe = caller->exe != "<unavailable>";
  std::filesystem::path callerPath;
  std::filesystem::path argv0Path;
  std::error_code ec;

  if (hasExe) {
    SPDLOG_TRACE("caller: {}", caller->exe);

    // Resolve the caller once so symlinked install locations compare equal.
    callerPath = std::filesystem::weakly_canonical(caller->exe, ec);
    if (ec) {
      report(*caller, "caller");
      return {std::errc::io_error, "cannot resolve caller executable"};
    }
  } else {
    // gpg-agent marks itself non-dumpable, so /proc/<pid>/exe is hidden even
    // from the same user. Its command line still names the started program.
    const auto end = caller->cmdline.find(' ');
    SPDLOG_TRACE("gpg caller: {}", caller->cmdline);
    const std::string argv0 = caller->cmdline.substr(0, end);
    if (argv0.empty()) {
      SPDLOG_TRACE("faulted: gpg caller cmdline empty");
      return {std::errc::io_error, "caller command line is empty"};
    }
    argv0Path = argv0;
    SPDLOG_TRACE("caller (exe unavailable): {}", caller->cmdline);
    SPDLOG_TRACE("gpg caller argv0: {}", argv0Path.string());
    const auto binary = Security::trusted_executable(
        std::filesystem::path("/usr/bin/gpg-agent"));
    if (binary) {
      const bool same = std::filesystem::equivalent(argv0Path, *binary, ec);
      if (!ec && same) {
        SPDLOG_TRACE("gpg caller argv0 passed match");
        return {std::errc{}, "ok"};
      }
    }
    SPDLOG_TRACE("gpg caller argv0 failure match");
  }

  // gpg-agent normally launches pinentry, but accept the GPG command-line
  // executables too in case they are configured to invoke it directly.
  constexpr const char *kGpgExecutables[] = {"gpg-agent", "gpg", "gpg2"};
  bool foundTrusted = false;
  for (const char *name : kGpgExecutables) {
    const auto binary =
        Security::trusted_executable(std::filesystem::path("/usr/bin") / name);
    if (!binary) {
      continue;
    }
    foundTrusted = true;

    SPDLOG_TRACE("{}: {}", name, binary->string());

    if (hasExe) {
      const bool same = std::filesystem::equivalent(callerPath, *binary, ec);
      if (ec) {
        return {std::errc::io_error,
                "cannot compare caller with a GPG executable"};
      }
      if (same) {
        return {std::errc{}, "ok"};
      }
      continue;
    }

    if (argv0Path.is_absolute()) {
      const auto trustedArg = Security::trusted_executable(argv0Path);
      if (!trustedArg) {
        return {std::errc::permission_denied,
                "caller is not a trusted GPG executable"};
      }
      const bool same = std::filesystem::equivalent(*trustedArg, *binary, ec);
      if (ec) {
        return {std::errc::io_error,
                "cannot compare caller with a GPG executable"};
      }
      if (same) {
        return {std::errc{}, "ok"};
      }
    }
  }

  if (foundTrusted) {
    return {std::errc::permission_denied, "caller is not a GPG executable"};
  }
  return {std::errc::io_error, "no trusted GPG executable found"};
}

SecurityVerdict Security::verify_ssh() const {
  const auto sshBinary = SSHhelper::locateBinary();
  if (!sshBinary) {
    return {std::errc::io_error,
            "ssh was not found in a trusted location"};
  }

  const auto caller = ProcessInfo::caller();
  if (!caller || caller->exe == "<unavailable>") {
    return {std::errc::io_error,
            "caller process or executable is unavailable"};
  }

  SPDLOG_TRACE("caller: {}", caller->exe);
  SPDLOG_TRACE("ssh: {}", sshBinary->string());

  // Resolve both sides so symlinked install locations compare equal.
  std::error_code ec;
  const auto callerPath = std::filesystem::weakly_canonical(caller->exe, ec);
  if (ec) {
    return {std::errc::io_error, "cannot resolve caller executable"};
  }

  const auto sshPath = std::filesystem::weakly_canonical(*sshBinary, ec);
  if (ec) {
    return {std::errc::io_error, "cannot resolve ssh"};
  }

  const bool same = std::filesystem::equivalent(callerPath, sshPath, ec);
  if (ec) {
    return {std::errc::io_error, "cannot compare caller with ssh"};
  }
  if (same) {
    return {std::errc{}, "ok"};
  }

  const auto sshAdd = SSHhelper::locateBinary("ssh-add");
  if (!sshAdd) {
    return {std::errc::io_error,
            "ssh-add was not found in a trusted location"};
  }
  const auto sshAddPath = std::filesystem::weakly_canonical(*sshAdd, ec);
  if (ec) {
    return {std::errc::io_error, "cannot resolve ssh-add"};
  }
  const bool sameAdd = std::filesystem::equivalent(callerPath, sshAddPath, ec);
  if (ec) {
    return {std::errc::io_error, "cannot compare caller with ssh-add"};
  }
  if (sameAdd) {
    return {std::errc{}, "ok"};
  }
  return {std::errc::permission_denied, "caller is not ssh or ssh-add"};
}

SecurityVerdict Security::verify_aws(pid_t pid) const {
  return AwsCliVerifier{}.verify(pid);
}

} // namespace methuselah
