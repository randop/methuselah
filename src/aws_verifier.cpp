#include "config.h"

#include "methuselah/aws_verifier.hpp"

#include "methuselah/process_info.hpp"

#include <spdlog/spdlog.h>

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

namespace methuselah {
namespace {

constexpr const char *kRootBundle = "/usr/local/aws-cli/v2/current/dist/aws";
constexpr const char *kServiceBundle =
    "/opt/methuselah/aws-cli/v2/current/dist/aws";
constexpr const char *kServiceAccount = "methuselah";

// Only string literals are accepted (see SecurityVerdict), so the returned
// reason can never dangle.
template <std::size_t N>
SecurityVerdict verdict(std::errc result, const char (&reason)[N]) {
  return SecurityVerdict{result, reason};
}

bool starts_with(std::string_view value, std::string_view prefix) {
  return value.substr(0, prefix.size()) == prefix;
}

std::string proc_link(pid_t pid, const char *leaf) {
  return "/proc/" + std::to_string(pid) + "/" + leaf;
}

// Exact names (or "NAME*" prefixes) that must not be present in the AWS CLI's
// start-up environment. Each either injects code into the process or lets
// the caller steer where, or over which trust store, credentials are sent.
constexpr std::array<std::string_view, 20> kForbiddenEnvironment = {
    "LD_*",              // loader injection: LD_PRELOAD, LD_LIBRARY_PATH, ...
    "PYTHON*",           // interpreter hooks: PYTHONPATH, PYTHONSTARTUP, ...
    "MALLOC_*",          // allocator hooks
    "GCONV_PATH",        // iconv module loading
    "LOCPATH",           // locale loading
    "NLSPATH",           // catalogue loading
    "HOSTALIASES",       // resolver redirection
    "AWS_ENDPOINT_URL*", // redirects every request, token included
    "AWS_DATA_PATH",     // overrides service models and endpoint defaults
    "AWS_CA_BUNDLE",     // replaces the TLS trust store
    "AWS_CONFIG_FILE",   // swaps in a different profile configuration
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "SSLKEYLOGFILE"}; // writes TLS session secrets to disk

// Long options that redirect, weaken, or dump credential handling.
constexpr std::string_view kAutoPromptOption = "--cli-auto-prompt";
constexpr std::string_view kAutoPromptEnv = "AWS_CLI_AUTO_PROMPT";
constexpr std::string_view kAutoPromptConfig = "cli_auto_prompt";
constexpr std::array<std::string_view, 5> kForbiddenOptions = {
    "--endpoint-url", "--ca-bundle", "--no-verify-ssl", "--debug",
    kAutoPromptOption};

// Global options that consume a separate value when written without '='.
// Keep in sync with the AWS CLI v2 global option table.
constexpr std::string_view kGlobalValueOptions[] = {"--profile",
                                                    "--region",
                                                    "--output",
                                                    "--query",
                                                    "--color",
                                                    "--cli-read-timeout",
                                                    "--cli-connect-timeout",
                                                    "--cli-binary-format",
                                                    "--cli-error-format"};

bool ascii_iequals(std::string_view value, std::string_view lowercase) {
  return std::equal(value.begin(), value.end(), lowercase.begin(),
                    lowercase.end(), [](char a, char b) {
                      return (a >= 'A' && a <= 'Z' ? a + ('a' - 'A') : a) == b;
                    });
}

bool name_matches(std::string_view name, std::string_view pattern) {
  if (!pattern.empty() && pattern.back() == '*') {
    return starts_with(name, pattern.substr(0, pattern.size() - 1));
  }
  return name == pattern;
}

constexpr std::size_t kSha256HexLength = 64;

bool is_hex_digest(std::string_view text) {
  return text.size() == kSha256HexLength &&
         std::all_of(text.begin(), text.end(),
                     [](unsigned char c) { return std::isxdigit(c) != 0; });
}

bool same_file(const struct stat &a, const struct stat &b) {
  return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

std::optional<uid_t> account_uid(const char *name) {
  long size = ::sysconf(_SC_GETPW_R_SIZE_MAX);
  std::vector<char> buffer(static_cast<std::size_t>(size > 0 ? size : 16384));
  struct passwd entry{};
  struct passwd *result = nullptr;
  if (::getpwnam_r(name, &entry, buffer.data(), buffer.size(), &result) != 0 ||
      result == nullptr) {
    return std::nullopt;
  }
  return entry.pw_uid;
}

std::string_view next_entry(std::string_view &environment) {
  const auto nul = environment.find('\0');
  const auto entry = environment.substr(0, nul);
  environment = nul == std::string_view::npos ? std::string_view{}
                                              : environment.substr(nul + 1);
  return entry;
}

bool same_proc_object(pid_t pid, const char *leaf) {
  struct stat caller{}, self{};
  return ::stat(proc_link(pid, leaf).c_str(), &caller) == 0 &&
         ::stat((std::string("/proc/self/") + leaf).c_str(), &self) == 0 &&
         same_file(caller, self);
}

std::string_view strip_config_indent(std::string_view text) {
  // RawConfigParser uses Python str.strip(), including Unicode whitespace.
  constexpr std::string_view unicode_space[] = {
      "\u0085", "\u00a0", "\u1680", "\u2000", "\u2001", "\u2002", "\u2003",
      "\u2004", "\u2005", "\u2006", "\u2007", "\u2008", "\u2009", "\u200a",
      "\u2028", "\u2029", "\u202f", "\u205f", "\u3000"};
  while (!text.empty()) {
    if (std::string_view(" \t\f\v\x1c\x1d\x1e\x1f").find(text.front()) !=
        std::string_view::npos) {
      text.remove_prefix(1);
      continue;
    }
    const auto space =
        std::find_if(std::begin(unicode_space), std::end(unicode_space),
                     [text](auto prefix) { return starts_with(text, prefix); });
    if (space == std::end(unicode_space)) {
      break;
    }
    text.remove_prefix(space->size());
  }
  return text;
}

SecurityVerdict verify_cli_config(std::string_view environment) {
  std::optional<std::string_view> home;
  while (!environment.empty()) {
    const auto entry = next_entry(environment);
    if (entry == "HOME" || starts_with(entry, "HOME=")) {
      if (home || entry == "HOME") {
        return verdict(std::errc::io_error, "cannot determine AWS CLI home");
      }
      home = entry.substr(5);
    }
  }
  if (!home || home->empty()) {
    return verdict(std::errc::io_error, "cannot determine AWS CLI home");
  }

  // The CLI caches full_config before invoking credential_process. Inspecting
  // a writable file now cannot tell us what the CLI loaded at startup.
  const auto trusted_home =
      Security::trusted_directory(std::filesystem::path(*home));
  if (!trusted_home) {
    return verdict(std::errc::permission_denied,
                   "AWS CLI home must be root controlled");
  }
  const auto config_dir = *trusted_home / ".aws";
  struct stat info{};
  if (::lstat(config_dir.c_str(), &info) != 0) {
    if (errno == ENOENT) {
      return verdict(std::errc{}, "ok");
    }
    return verdict(std::errc::io_error,
                   "cannot inspect AWS CLI config directory");
  }
  const auto trusted_dir = Security::trusted_directory(config_dir);
  if (!trusted_dir) {
    return verdict(std::errc::io_error,
                   "cannot establish trust in AWS CLI config directory");
  }
  // Both files feed the scoped profile used to resolve auto-prompt. Only
  // config can supply a top-level plugins section.
  for (const auto *name : {"config", "credentials"}) {
    const auto path = *trusted_dir / name;
    if (::lstat(path.c_str(), &info) != 0) {
      if (errno == ENOENT) {
        continue;
      }
      return verdict(std::errc::io_error, "cannot inspect AWS CLI config file");
    }
    const auto trusted_path = Security::trusted_file(path);
    if (!trusted_path) {
      return verdict(std::errc::io_error,
                     "cannot establish trust in AWS CLI config file");
    }
    std::ifstream stream(*trusted_path);
    const auto result = AwsCliVerifier::scan_cli_config(
        stream, std::string_view(name) == "config");
    if (!result.passed()) {
      return result;
    }
  }
  return verdict(std::errc{}, "ok");
}

// libffi legitimately backs closure trampolines with a memfd.
bool allowed_special_mapping(std::string_view path) {
  constexpr std::string_view kDeleted = " (deleted)";
  if (path.size() > kDeleted.size() &&
      path.substr(path.size() - kDeleted.size()) == kDeleted) {
    path.remove_suffix(kDeleted.size());
    return path == "/memfd:libffi";
  }
  return false;
}

} // namespace

SecurityVerdict AwsCliVerifier::scan_cli_config(std::istream &stream,
                                                bool check_plugins) {
  for (std::string line; std::getline(stream, line);) {
    // Python opens the config in universal newline mode.
    std::string_view remaining(line);
    while (!remaining.empty()) {
      const auto cr = remaining.find('\r');
      const auto text = strip_config_indent(remaining.substr(0, cr));
      remaining = cr == std::string_view::npos ? std::string_view{}
                                               : remaining.substr(cr + 1);
      // RawConfigParser matches from the start of the trimmed line through
      // the last closing bracket. It accepts trailing text after that bracket.
      constexpr std::string_view header = "[plugins]";
      if (check_plugins && starts_with(text, header) &&
          text.rfind(']') == header.size() - 1) {
        return verdict(std::errc::permission_denied,
                       "AWS CLI plugin configuration is not allowed");
      }
      // RawConfigParser lowercases option names and accepts both separators.
      // Check every profile, including inherited settings in [DEFAULT].
      if (text.size() >= kAutoPromptConfig.size() &&
          ascii_iequals(text.substr(0, kAutoPromptConfig.size()),
                        kAutoPromptConfig)) {
        const auto assignment =
            strip_config_indent(text.substr(kAutoPromptConfig.size()));
        if (!assignment.empty() &&
            (assignment.front() == '=' || assignment.front() == ':')) {
          const auto value = strip_config_indent(assignment.substr(1));
          // Allow an explicit off. A continued value cannot turn off into on.
          if (!ascii_iequals(value.substr(0, 3), "off") ||
              !strip_config_indent(value.substr(3)).empty()) {
            return verdict(std::errc::permission_denied,
                           "AWS CLI auto-prompt configuration is not allowed");
          }
        }
      }
    }
  }
  if (stream.bad() || !stream.eof()) {
    return verdict(std::errc::io_error, "cannot read AWS CLI config file");
  }
  return verdict(std::errc{}, "ok");
}

AwsCliVerifier::Options AwsCliVerifier::default_options() {
  Options options;
  options.candidates = {
      kServiceBundle,
      kRootBundle,
      "/usr/local/bin/aws",
      "/usr/bin/aws",
  };
  options.pin_file = "/etc/methuselah/aws-cli.sha256";
  if (const auto service = account_uid(kServiceAccount);
      service && *service != 0 && *service != ::geteuid()) {
    options.install_owners.push_back(*service);
  }
  return options;
}

std::optional<std::string>
AwsCliVerifier::forbidden_environment(std::string_view environment,
                                      std::string_view bundle_library_path) {
  bool seen_library_path = false;
  while (!environment.empty()) {
    const auto entry = next_entry(environment);
    const auto equals = entry.find('=');
    const auto name = entry.substr(0, equals);
    if (name == kAutoPromptEnv &&
        (equals == std::string_view::npos ||
         !ascii_iequals(entry.substr(equals + 1), "off"))) {
      return std::string(name);
    }
    if (name == "LD_LIBRARY_PATH" && equals != std::string_view::npos &&
        !seen_library_path && !bundle_library_path.empty() &&
        bundle_library_path.find_first_of(":;$") == std::string_view::npos &&
        entry.substr(equals + 1) == bundle_library_path) {
      // PyInstaller prepends the bundle directory to any inherited value and
      // preserves the original in LD_LIBRARY_PATH_ORIG, which stays forbidden.
      seen_library_path = true;
      continue;
    }
    for (const auto pattern : kForbiddenEnvironment) {
      if (name_matches(name, pattern)) {
        return std::string(name);
      }
    }
  }
  return std::nullopt;
}

std::optional<std::string>
AwsCliVerifier::forbidden_arguments(const std::vector<std::string> &args) {
  bool after_delimiter = false;
  bool value_expected = false;
  std::string_view command;
  bool have_subcommand = false;
  for (std::size_t i = 1; i < args.size(); ++i) {
    const std::string_view arg = args[i];
    // The entry point checks for the exact auto-prompt flag before parsing,
    // even after a delimiter. It can replace the command in argv.
    if (arg == kAutoPromptOption) {
      return args[i];
    }
    if (arg == "--") {
      after_delimiter = true;
      value_expected = false;
      continue;
    }
    if (!after_delimiter && starts_with(arg, "--")) {
      const auto equals = arg.find('=');
      const auto name = arg.substr(0, equals);
      for (const auto forbidden : kForbiddenOptions) {
        // argparse accepts unambiguous prefixes such as "--endpoint".
        if (name.size() >= 3 && starts_with(forbidden, name)) {
          return args[i];
        }
      }
      value_expected =
          equals == std::string_view::npos &&
          std::any_of(
              std::begin(kGlobalValueOptions), std::end(kGlobalValueOptions),
              [name](auto option) { return starts_with(option, name); });
      continue;
    }
    if (value_expected) {
      value_expected = false;
      continue;
    }
    if (starts_with(arg, "-")) {
      continue;
    }
    // Each parser can consume a delimiter before its command name. Resolve
    // those names before treating tokens past a delimiter as positional data.
    if (arg == "export-credentials" &&
        (!after_delimiter || (command == "configure" && !have_subcommand))) {
      return args[i];
    }
    if (command.empty()) {
      command = arg;
    } else {
      have_subcommand = true;
    }
  }
  return std::nullopt;
}

std::vector<std::string>
AwsCliVerifier::executable_mapping_paths(std::string_view maps) {
  std::set<std::string> unique;
  while (!maps.empty()) {
    const auto nl = maps.find('\n');
    std::string_view line = maps.substr(0, nl);
    maps =
        nl == std::string_view::npos ? std::string_view{} : maps.substr(nl + 1);

    // "start-end perms offset dev inode   path": the path may contain spaces.
    std::size_t pos = 0;
    std::string_view fields[5];
    bool complete = true;
    for (auto &field : fields) {
      while (pos < line.size() && line[pos] == ' ') {
        ++pos;
      }
      const auto end = line.find(' ', pos);
      if (pos >= line.size() || end == std::string_view::npos) {
        complete = false;
        break;
      }
      field = line.substr(pos, end - pos);
      pos = end;
    }
    if (!complete) {
      continue;
    }
    while (pos < line.size() && line[pos] == ' ') {
      ++pos;
    }
    const std::string_view path = line.substr(pos);
    const std::string_view perms = fields[1];
    if (perms.size() < 3 || perms[2] != 'x' || path.empty() ||
        path.front() != '/') {
      continue; // not executable, anonymous, or [vdso]/[stack]-style
    }
    unique.emplace(path);
  }
  return {unique.begin(), unique.end()};
}

std::optional<std::vector<std::string>>
AwsCliVerifier::parse_pin_file(std::string_view text) {
  std::vector<std::string> digests;
  while (!text.empty()) {
    const auto nl = text.find('\n');
    std::string_view line = text.substr(0, nl);
    text =
        nl == std::string_view::npos ? std::string_view{} : text.substr(nl + 1);
    while (!line.empty() &&
           std::isspace(static_cast<unsigned char>(line.back())) != 0) {
      line.remove_suffix(1);
    }
    while (!line.empty() &&
           std::isspace(static_cast<unsigned char>(line.front())) != 0) {
      line.remove_prefix(1);
    }
    if (line.empty() || line.front() == '#') {
      continue;
    }

    const auto space = line.find_first_of(" \t");
    const std::string_view digest = line.substr(0, space);
    if (!is_hex_digest(digest)) {
      return std::nullopt;
    }
    // Build the lowercase copy element by element. Copy-constructing from the
    // view and transforming in place makes GCC (-Wstringop-overread, LTO)
    // lose the 64-character bound that is_hex_digest() just established.
    std::string lowered(kSha256HexLength, '\0');
    for (std::size_t i = 0; i < kSha256HexLength; ++i) {
      lowered[i] = static_cast<char>(
          std::tolower(static_cast<unsigned char>(digest[i])));
    }
    digests.push_back(std::move(lowered));
  }
  if (digests.empty()) {
    return std::nullopt;
  }
  return digests;
}

std::optional<std::string> AwsCliVerifier::sha256_hex(int fd) {
  if (::sodium_init() < 0) {
    return std::nullopt;
  }
  crypto_hash_sha256_state state;
  crypto_hash_sha256_init(&state);

  std::array<unsigned char, 65536> buffer;
  for (;;) {
    const ssize_t n = ::read(fd, buffer.data(), buffer.size());
    if (n > 0) {
      crypto_hash_sha256_update(&state, buffer.data(),
                                static_cast<unsigned long long>(n));
      continue;
    }
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n < 0) {
      return std::nullopt;
    }
    break;
  }

  std::array<unsigned char, crypto_hash_sha256_BYTES> digest;
  crypto_hash_sha256_final(&state, digest.data());
  char hex[crypto_hash_sha256_BYTES * 2 + 1];
  ::sodium_bin2hex(hex, sizeof(hex), digest.data(), digest.size());
  return std::string(hex);
}

SecurityVerdict AwsCliVerifier::verify(pid_t pid) const {
  if (pid <= 1) {
    return verdict(std::errc::io_error, "no AWS CLI parent process");
  }

  // Tracer: a same-uid debugger could rewrite the CLI after it passes.
  const auto status = ProcessInfo::readProc(pid, "status");
  if (!status) {
    return verdict(std::errc::io_error, "cannot read caller status");
  }
  const auto tracer = status->find("TracerPid:");
  if (tracer == std::string::npos) {
    return verdict(std::errc::io_error, "caller status lacks TracerPid");
  }
  if (std::atol(status->c_str() + tracer + 10) != 0) {
    return verdict(std::errc::permission_denied, "caller is being traced");
  }

  // Identity of the running image, by inode.
  const std::string exeLink = proc_link(pid, "exe");
  struct stat running{};
  if (::stat(exeLink.c_str(), &running) != 0) {
    return verdict(std::errc::io_error, "cannot inspect caller executable");
  }
  std::error_code ec;
  const auto linkTarget = std::filesystem::read_symlink(exeLink, ec);
  if (ec) {
    return verdict(std::errc::io_error, "cannot read caller executable link");
  }
  if (linkTarget.string().ends_with(" (deleted)")) {
    return verdict(std::errc::permission_denied,
                   "caller executable was replaced on disk");
  }

  const TrustPolicy install_trust{options_.install_owners};
  bool anyTrusted = false;
  bool matched = false;
  std::string bundle_library_path;
  for (const auto &candidate : options_.candidates) {
    const auto trusted = Security::trusted_executable(candidate, install_trust);
    if (!trusted || trusted->filename() != options_.required_name) {
      continue;
    }
    anyTrusted = true;
    struct stat expected{};
    if (::stat(trusted->c_str(), &expected) == 0 &&
        same_file(running, expected)) {
      matched = true;
      const bool official_bundle =
          candidate == std::filesystem::path(kServiceBundle) ||
          candidate == std::filesystem::path(kRootBundle);
      // The official Linux onedir bundle uses contents_directory='.'; its
      // bootloader sets LD_LIBRARY_PATH to the actual executable directory.
      if (official_bundle && *trusted == linkTarget) {
        bundle_library_path = trusted->parent_path().string();
      }
      break;
    }
  }
  if (!anyTrusted) {
    return verdict(std::errc::io_error,
                   "no trusted AWS CLI v2 installation found");
  }
  if (!matched) {
    return verdict(std::errc::permission_denied,
                   "caller is not a trusted AWS CLI v2");
  }

  // Optional digest pin of the running image.
  struct stat pinInfo{};
  if (::lstat(options_.pin_file.c_str(), &pinInfo) == 0) {
    const auto pinPath = Security::trusted_file(options_.pin_file);
    if (!pinPath) {
      return verdict(std::errc::io_error, "AWS CLI pin file is not root-owned");
    }
    const int pinFd = ::open(pinPath->c_str(), O_RDONLY | O_CLOEXEC);
    if (pinFd < 0) {
      return verdict(std::errc::io_error, "cannot open AWS CLI pin file");
    }
    std::string text;
    char buffer[1024];
    ssize_t n;
    while ((n = ::read(pinFd, buffer, sizeof(buffer))) > 0 &&
           text.size() < (1U << 16)) {
      text.append(buffer, static_cast<std::size_t>(n));
    }
    ::close(pinFd);
    const auto pins = parse_pin_file(text);
    if (!pins) {
      return verdict(std::errc::io_error,
                     "AWS CLI pin file is empty or invalid");
    }

    const int exeFd = ::open(exeLink.c_str(), O_RDONLY | O_CLOEXEC);
    if (exeFd < 0) {
      return verdict(std::errc::io_error, "cannot open caller executable");
    }
    const auto digest = sha256_hex(exeFd);
    ::close(exeFd);
    if (!digest) {
      return verdict(std::errc::io_error, "cannot hash caller executable");
    }
    if (std::find(pins->begin(), pins->end(), *digest) == pins->end()) {
      return verdict(std::errc::permission_denied,
                     "AWS CLI does not match its pinned SHA-256 (modified or "
                     "upgraded without refreshing the pin)");
    }
  } else if (errno != ENOENT) {
    return verdict(std::errc::io_error, "cannot inspect AWS CLI pin file");
  }

  const auto args = ProcessInfo::argv(pid);
  if (!args) {
    return verdict(std::errc::io_error, "cannot read caller arguments");
  }
  if (const auto bad = forbidden_arguments(*args)) {
    SPDLOG_TRACE("aws caller argument not allowed: {}", *bad);
    return verdict(std::errc::permission_denied,
                   "AWS CLI argument not allowed");
  }

  const auto environment = ProcessInfo::readProc(pid, "environ", 4U << 20);
  if (!environment) {
    return verdict(std::errc::io_error, "cannot read caller environment");
  }
  if (!same_proc_object(pid, "root") || !same_proc_object(pid, "ns/mnt")) {
    return verdict(std::errc::io_error,
                   "cannot verify caller filesystem context");
  }
  if (const auto bad =
          forbidden_environment(*environment, bundle_library_path)) {
    SPDLOG_TRACE("aws caller environment variable not allowed: {}", *bad);
    return verdict(std::errc::permission_denied,
                   "AWS CLI environment variable not allowed");
  }

  const auto cli_config = verify_cli_config(*environment);
  if (!cli_config.passed()) {
    return cli_config;
  }

  const auto maps = ProcessInfo::readProc(pid, "maps", 16U << 20);
  if (!maps) {
    return verdict(std::errc::io_error, "cannot read caller memory map");
  }
  for (const auto &path : executable_mapping_paths(*maps)) {
    if (allowed_special_mapping(path)) {
      continue;
    }
    if (!Security::trusted_file(path, install_trust)) {
      SPDLOG_TRACE("aws caller has untrusted code mapped: {}", path);
      return verdict(std::errc::permission_denied,
                     "AWS CLI has untrusted code mapped");
    }
  }

  // The caller must still be the same process we started inspecting.
  struct stat after{};
  if (::stat(exeLink.c_str(), &after) != 0 || !same_file(running, after)) {
    return verdict(std::errc::io_error, "caller changed during verification");
  }
  return verdict(std::errc{}, "ok");
}

} // namespace methuselah
