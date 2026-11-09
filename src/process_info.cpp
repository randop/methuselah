#include "methuselah/process_info.hpp"

#include <unistd.h>

#include <charconv>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string_view>
#include <system_error>

namespace methuselah {

namespace {

std::filesystem::path procPath(pid_t pid, const char *leaf) {
  return std::filesystem::path("/proc") / std::to_string(pid) / leaf;
}

} // namespace

pid_t ProcessInfo::self() noexcept { return ::getpid(); }
pid_t ProcessInfo::parent() noexcept { return ::getppid(); }

std::optional<pid_t> ProcessInfo::parentOf(pid_t pid) {
  std::ifstream f(procPath(pid, "stat"));
  if (!f) {
    return std::nullopt;
  }

  std::string line;
  std::getline(f, line);

  // Format: "pid (comm) state ppid ...". comm may contain spaces or ')',
  // so parse everything after the last ')'.
  auto close = line.rfind(')');
  if (close == std::string::npos) {
    return std::nullopt;
  }

  std::string_view rest(line);
  rest.remove_prefix(close + 1);

  // Skip leading spaces, then the state character.
  auto skip = [&rest] {
    while (!rest.empty() && rest.front() == ' ') {
      rest.remove_prefix(1);
    }
  };
  skip();
  if (rest.empty()) {
    return std::nullopt;
  }
  rest.remove_prefix(1); // state
  skip();

  long ppid = 0;
  auto [end, ec] =
      std::from_chars(rest.data(), rest.data() + rest.size(), ppid);
  if (ec != std::errc{}) {
    return std::nullopt;
  }
  return static_cast<pid_t>(ppid);
}

std::optional<std::string> ProcessInfo::exePath(pid_t pid) {
  std::error_code ec;
  auto target = std::filesystem::read_symlink(procPath(pid, "exe"), ec);
  if (ec) {
    return std::nullopt;
  }
  return target.string();
}

std::optional<std::string> ProcessInfo::cmdline(pid_t pid) {
  std::ifstream f(procPath(pid, "cmdline"), std::ios::binary);
  if (!f) {
    return std::nullopt;
  }

  std::string raw((std::istreambuf_iterator<char>(f)),
                  std::istreambuf_iterator<char>());
  for (char &c : raw) {
    if (c == '\0') {
      c = ' ';
    }
  }
  while (!raw.empty() && raw.back() == ' ') {
    raw.pop_back();
  }
  return raw;
}

std::optional<ProcessInfo::Entry> ProcessInfo::describe(pid_t pid) {
  auto ppid = parentOf(pid);
  if (!ppid) {
    return std::nullopt;
  }

  Entry e;
  e.pid = pid;
  e.ppid = *ppid;
  e.exe = exePath(pid).value_or("<unavailable>");
  e.cmdline = cmdline(pid).value_or("");
  return e;
}

std::vector<ProcessInfo::Entry> ProcessInfo::ancestry(pid_t pid,
                                                      std::size_t maxDepth) {
  std::vector<Entry> chain;
  if (pid == 0) {
    pid = self();
  }

  auto next = parentOf(pid);
  while (next && *next > 1 && chain.size() < maxDepth) {
    auto e = describe(*next);
    if (!e) {
      break;
    }
    chain.push_back(*e);
    next = parentOf(e->pid);
  }
  return chain;
}

std::optional<ProcessInfo::Entry> ProcessInfo::caller() {
  auto p = parent();
  return p > 1 ? describe(p) : std::nullopt;
}

} // namespace methuselah
