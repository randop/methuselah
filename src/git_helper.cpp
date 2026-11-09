#include "methuselah/git_helper.hpp"

#include <cctype>
#include <cerrno>
#include <cstddef>
#include <string>
#include <system_error>

#include <fcntl.h>
#include <spawn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

namespace methuselah {
namespace {

constexpr std::size_t kMaxExecPathOutput = 4096;

// Keep pipe descriptors above stderr so the spawn actions cannot accidentally
// close the child's stdout when the parent started with closed standard FDs.
bool moveAboveStandardDescriptors(int &fd) {
  if (fd > STDERR_FILENO) {
    return true;
  }

  const int replacement = ::fcntl(fd, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
  if (replacement == -1) {
    return false;
  }

  ::close(fd);
  fd = replacement;
  return true;
}

void trimWhitespace(std::string &value) {
  const auto isSpace = [](unsigned char ch) { return std::isspace(ch) != 0; };

  while (!value.empty() && isSpace(static_cast<unsigned char>(value.back()))) {
    value.pop_back();
  }

  std::size_t first = 0;
  while (first < value.size() &&
         isSpace(static_cast<unsigned char>(value[first]))) {
    ++first;
  }

  value.erase(0, first);
}

} // namespace

std::optional<GitHelper::Path>
GitHelper::execPath(std::string_view gitExecutable) {
  const auto output = runGitExecPath(gitExecutable);
  if (!output || output->empty()) {
    return std::nullopt;
  }

  std::error_code ec;
  Path directory(*output);

  if (directory.is_relative()) {
    directory = std::filesystem::absolute(directory, ec);
    if (ec) {
      return std::nullopt;
    }
  }

  return directory;
}

std::optional<GitHelper::Path>
GitHelper::locateRemoteHttp(std::string_view gitExecutable) {
  const auto directory = execPath(gitExecutable);
  if (!directory) {
    return std::nullopt;
  }

  const Path helper = *directory / "git-remote-http";

  std::error_code ec;
  if (!std::filesystem::is_regular_file(helper, ec) || ec) {
    return std::nullopt;
  }

  if (::access(helper.c_str(), X_OK) != 0) {
    return std::nullopt;
  }

  return helper;
}

bool GitHelper::hasRemoteHttp(std::string_view gitExecutable) {
  return locateRemoteHttp(gitExecutable).has_value();
}

std::optional<std::string>
GitHelper::runGitExecPath(std::string_view gitExecutable) {
  if (gitExecutable.empty() ||
      gitExecutable.find('\0') != std::string_view::npos) {
    return std::nullopt;
  }

  const std::string executable(gitExecutable);

  int pipeFd[2];
  if (::pipe(pipeFd) == -1) {
    return std::nullopt;
  }

  if (!moveAboveStandardDescriptors(pipeFd[0]) ||
      !moveAboveStandardDescriptors(pipeFd[1])) {
    ::close(pipeFd[0]);
    ::close(pipeFd[1]);
    return std::nullopt;
  }

  posix_spawn_file_actions_t actions;
  int rc = ::posix_spawn_file_actions_init(&actions);
  if (rc != 0) {
    ::close(pipeFd[0]);
    ::close(pipeFd[1]);
    return std::nullopt;
  }

  rc = ::posix_spawn_file_actions_adddup2(&actions, pipeFd[1], STDOUT_FILENO);

  if (rc == 0) {
    rc = ::posix_spawn_file_actions_addclose(&actions, pipeFd[0]);
  }

  if (rc == 0) {
    rc = ::posix_spawn_file_actions_addclose(&actions, pipeFd[1]);
  }

  if (rc != 0) {
    ::posix_spawn_file_actions_destroy(&actions);
    ::close(pipeFd[0]);
    ::close(pipeFd[1]);
    return std::nullopt;
  }

  char option[] = "--exec-path";
  char *argv[] = {const_cast<char *>(executable.c_str()), option, nullptr};

  pid_t child = -1;
  rc = ::posix_spawnp(&child, executable.c_str(), &actions, nullptr, argv,
                      environ);

  ::posix_spawn_file_actions_destroy(&actions);
  ::close(pipeFd[1]);

  if (rc != 0) {
    ::close(pipeFd[0]);
    return std::nullopt;
  }

  std::string output;
  char buffer[256];
  bool readFailed = false;
  bool outputTooLarge = false;

  for (;;) {
    const ssize_t count = ::read(pipeFd[0], buffer, sizeof(buffer));

    if (count > 0) {
      const auto bytes = static_cast<std::size_t>(count);
      if (output.size() + bytes <= kMaxExecPathOutput) {
        output.append(buffer, bytes);
      } else {
        outputTooLarge = true; // Continue draining to avoid blocking Git.
      }
      continue;
    }

    if (count == 0) {
      break;
    }

    if (errno == EINTR) {
      continue;
    }

    readFailed = true;
    break;
  }

  ::close(pipeFd[0]);

  int status = 0;
  pid_t waited;
  do {
    waited = ::waitpid(child, &status, 0);
  } while (waited == -1 && errno == EINTR);

  if (readFailed || outputTooLarge || waited == -1 || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 0) {
    return std::nullopt;
  }

  trimWhitespace(output);
  return output;
}

} // namespace methuselah
