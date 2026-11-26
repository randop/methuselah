#include "config.h"

#include "methuselah/aws_cli_verifier.hpp"

#include "methuselah/fd_io.hpp"
#include "methuselah/process_info.hpp"
#include "methuselah/text_util.hpp"

#include <spdlog/spdlog.h>

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <filesystem>
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

constexpr std::size_t kMaxPinBytes = 1U << 16;
constexpr std::size_t kMaxFdInfoBytes = 4096;
constexpr std::size_t kMaxEnvironBytes = 4U << 20;
constexpr std::size_t kMaxMapsBytes = 16U << 20;

using strutil::ascii_iequals;

std::string proc_link(pid_t pid, const char *leaf) {
  return "/proc/" + std::to_string(pid) + "/" + leaf;
}

// Exact names (or "NAME*" prefixes) that must not be present in the AWS CLI's
// start-up environment. Each either injects code into the process or lets
// the caller steer where, or over which trust store, credentials are sent.
constexpr auto kForbiddenEnvironment = std::to_array<std::string_view>(
    {"LD_*",              // loader injection: LD_PRELOAD, LD_LIBRARY_PATH, ...
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
     "OPENSSL_*",       // OPENSSL_CONF/MODULES/ENGINES load code or swap trust
     "SSLKEYLOGFILE"}); // writes TLS session secrets to disk

constexpr std::string_view kAutoPromptEnv = "AWS_CLI_AUTO_PROMPT";

// Every other AWS_* variable can steer endpoints, credentials sources or
// service models, so the AWS CLI's AWS_* namespace is deny-by-default. These
// are the only ones that cannot move credentials or load anything.
// AWS_CLI_AUTO_PROMPT is vetted separately: only "off" gets this far.
constexpr auto kAllowedAwsEnvironment = std::to_array<std::string_view>(
    {"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION",
     "AWS_DEFAULT_OUTPUT", "AWS_PAGER", "AWS_MAX_ATTEMPTS", "AWS_RETRY_MODE",
     "AWS_EC2_METADATA_DISABLED", "AWS_CLI_FILE_ENCODING", kAutoPromptEnv});

// Long options that redirect, weaken, or dump credential handling.
constexpr std::string_view kAutoPromptOption = "--cli-auto-prompt";
constexpr std::string_view kAutoPromptConfig = "cli_auto_prompt";
constexpr auto kForbiddenOptions = std::to_array<std::string_view>(
    {"--endpoint-url", "--ca-bundle", "--no-verify-ssl", "--debug",
     kAutoPromptOption});

// Global options that consume a separate value when written without '='.
// Keep in sync with the AWS CLI v2 global option table.
constexpr auto kGlobalValueOptions = std::to_array<std::string_view>(
    {"--profile", "--region", "--output", "--query", "--color",
     "--cli-read-timeout", "--cli-connect-timeout", "--cli-binary-format",
     "--cli-error-format"});

bool name_matches(std::string_view name, std::string_view pattern) {
  if (!pattern.empty() && pattern.back() == '*') {
    return name.starts_with(pattern.substr(0, pattern.size() - 1));
  }
  return name == pattern;
}

constexpr std::size_t kSha256HexLength = 64;

bool is_hex_digest(std::string_view text) {
  return text.size() == kSha256HexLength && strutil::is_hex(text);
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
                     [text](auto prefix) { return text.starts_with(prefix); });
    if (space == std::end(unicode_space)) {
      break;
    }
    text.remove_prefix(space->size());
  }
  return text;
}

// HOME exactly as the AWS CLI will see it. nullopt when it is missing, empty,
// has no value, or is given twice (so the scan could look at the wrong place).
std::optional<std::string_view>
home_from_environment(std::string_view environment) {
  constexpr std::string_view kPrefix = "HOME=";
  std::optional<std::string_view> home;
  while (!environment.empty()) {
    const auto entry = next_entry(environment);
    if (entry != "HOME" && !entry.starts_with(kPrefix)) {
      continue;
    }
    if (home || entry == "HOME") {
      return std::nullopt;
    }
    home = entry.substr(kPrefix.size());
  }
  if (!home || home->empty()) {
    return std::nullopt;
  }
  return home;
}

// Scans one file of the CLI's config directory, if it exists.
SecurityVerdict scan_config_file(const std::filesystem::path &path,
                                 bool check_plugins) {
  struct stat info{};
  if (::lstat(path.c_str(), &info) != 0) {
    if (errno == ENOENT) {
      return SecurityVerdict(std::errc{}, "ok");
    }
    return SecurityVerdict(std::errc::io_error,
                           "cannot inspect AWS CLI config file");
  }
  const auto trusted_path = Security::trusted_file(path);
  if (!trusted_path) {
    return SecurityVerdict(std::errc::io_error,
                           "cannot establish trust in AWS CLI config file");
  }
  std::ifstream stream(*trusted_path);
  return AwsCliVerifier::scan_cli_config(stream, check_plugins);
}

SecurityVerdict verify_cli_config(std::string_view environment) {
  const auto home = home_from_environment(environment);
  if (!home) {
    return SecurityVerdict(std::errc::io_error,
                           "cannot determine AWS CLI home");
  }

  // The CLI caches full_config before invoking credential_process. Inspecting
  // a writable file now cannot tell us what the CLI loaded at startup.
  const auto trusted_home =
      Security::trusted_directory(std::filesystem::path(*home));
  if (!trusted_home) {
    return SecurityVerdict(
        std::errc::permission_denied,
        "AWS CLI home must be root controlled (set HOME, see docs/aws.md)");
  }
  const auto config_dir = *trusted_home / ".aws";
  struct stat info{};
  if (::lstat(config_dir.c_str(), &info) != 0) {
    if (errno == ENOENT) {
      return SecurityVerdict(std::errc{}, "ok");
    }
    return SecurityVerdict(std::errc::io_error,
                           "cannot inspect AWS CLI config directory");
  }
  const auto trusted_dir = Security::trusted_directory(config_dir);
  if (!trusted_dir) {
    return SecurityVerdict(
        std::errc::io_error,
        "cannot establish trust in AWS CLI config directory");
  }
  // Both files feed the scoped profile used to resolve auto-prompt. Only
  // config can supply a top-level plugins section.
  for (const auto *name : {"config", "credentials"}) {
    const auto result = scan_config_file(*trusted_dir / name,
                                         std::string_view(name) == "config");
    if (!result.passed()) {
      return result;
    }
  }
  return SecurityVerdict(std::errc{}, "ok");
}

struct MapEntry {
  std::string_view perms;
  std::string_view path;
};

// "start-end perms offset dev inode   path": the path may contain spaces and
// is empty for anonymous memory. Lines that do not have the five leading
// fields are not map entries.
std::optional<MapEntry> parse_map_line(std::string_view line) {
  std::size_t pos = 0;
  std::string_view fields[5];
  for (auto &field : fields) {
    while (pos < line.size() && line[pos] == ' ') {
      ++pos;
    }
    const auto end = line.find(' ', pos);
    if (pos >= line.size() || end == std::string_view::npos) {
      return std::nullopt;
    }
    field = line.substr(pos, end - pos);
    pos = end;
  }
  while (pos < line.size() && line[pos] == ' ') {
    ++pos;
  }
  return MapEntry{fields[1], line.substr(pos)};
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

// RawConfigParser matches "[plugins]" from the start of the trimmed line
// through the last closing bracket. It accepts trailing text after that
// bracket.
bool is_plugins_header(std::string_view text) {
  constexpr std::string_view header = "[plugins]";
  return text.starts_with(header) && text.rfind(']') == header.size() - 1;
}

// RawConfigParser lowercases option names and accepts both separators. True
// when `text` assigns anything other than an explicit "off" to auto-prompt.
bool enables_auto_prompt(std::string_view text) {
  if (text.size() < kAutoPromptConfig.size() ||
      !ascii_iequals(text.substr(0, kAutoPromptConfig.size()),
                     kAutoPromptConfig)) {
    return false;
  }
  const auto assignment =
      strip_config_indent(text.substr(kAutoPromptConfig.size()));
  if (assignment.empty() ||
      (assignment.front() != '=' && assignment.front() != ':')) {
    return false;
  }
  const auto value = strip_config_indent(assignment.substr(1));
  // Allow an explicit off. A continued value cannot turn off into on.
  return !ascii_iequals(value.substr(0, 3), "off") ||
         !strip_config_indent(value.substr(3)).empty();
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
      if (check_plugins && is_plugins_header(text)) {
        return SecurityVerdict(std::errc::permission_denied,
                               "AWS CLI plugin configuration is not allowed");
      }
      // Check every profile, including inherited settings in [DEFAULT].
      if (enables_auto_prompt(text)) {
        return SecurityVerdict(
            std::errc::permission_denied,
            "AWS CLI auto-prompt configuration is not allowed");
      }
    }
  }
  if (stream.bad() || !stream.eof()) {
    return SecurityVerdict(std::errc::io_error,
                           "cannot read AWS CLI config file");
  }
  return SecurityVerdict(std::errc{}, "ok");
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
  options.ptrace_waiver_file = "/etc/methuselah/allow-weak-ptrace";
  options.anonymous_exec_waiver_file = "/etc/methuselah/allow-anonymous-exec";
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
    if (name.starts_with("AWS_") &&
        std::find(kAllowedAwsEnvironment.begin(), kAllowedAwsEnvironment.end(),
                  name) == kAllowedAwsEnvironment.end()) {
      return std::string(name);
    }
    if (std::any_of(
            kForbiddenEnvironment.begin(), kForbiddenEnvironment.end(),
            [name](auto pattern) { return name_matches(name, pattern); })) {
      return std::string(name);
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
    if (!after_delimiter && arg.starts_with("--")) {
      const auto equals = arg.find('=');
      const auto name = arg.substr(0, equals);
      // argparse accepts unambiguous prefixes such as "--endpoint".
      if (name.size() >= 3 &&
          std::any_of(
              kForbiddenOptions.begin(), kForbiddenOptions.end(),
              [name](auto forbidden) { return forbidden.starts_with(name); })) {
        return args[i];
      }
      value_expected =
          equals == std::string_view::npos &&
          std::any_of(kGlobalValueOptions.begin(), kGlobalValueOptions.end(),
                      [name](auto option) { return option.starts_with(name); });
      continue;
    }
    if (value_expected) {
      value_expected = false;
      continue;
    }
    if (arg.starts_with("-")) {
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
    const auto entry = parse_map_line(strutil::next_line(maps));
    if (!entry) {
      continue;
    }
    if (entry->perms.size() < 3 || entry->perms[2] != 'x' ||
        entry->path.empty() || entry->path.front() != '/') {
      continue; // not executable, anonymous, or [vdso]/[stack]-style
    }
    unique.emplace(entry->path);
  }
  return {unique.begin(), unique.end()};
}

AwsCliVerifier::UnsafeMapping
AwsCliVerifier::unsafe_mapping(std::string_view maps) {
  auto anonymous_mapping = UnsafeMapping::none;
  while (!maps.empty()) {
    const auto entry = parse_map_line(strutil::next_line(maps));
    if (!entry || entry->perms.size() < 3 || entry->perms[2] != 'x' ||
        entry->path == "[vdso]" || entry->path == "[vsyscall]") {
      continue;
    }
    const bool anonymous = entry->path.empty() || entry->path.front() != '/';
    if (!anonymous && entry->perms[1] == 'w') {
      return UnsafeMapping::file_writable_executable;
    }
    if (anonymous && anonymous_mapping == UnsafeMapping::none) {
      anonymous_mapping = entry->perms[1] == 'w'
                              ? UnsafeMapping::anonymous_writable_executable
                              : UnsafeMapping::anonymous_executable;
    }
  }
  return anonymous_mapping;
}

std::optional<int> AwsCliVerifier::parse_ptrace_scope(std::string_view text) {
  while (!text.empty() && (text.back() == '\n' || text.back() == ' ')) {
    text.remove_suffix(1);
  }
  int value = 0;
  const auto [end, ec] =
      std::from_chars(text.data(), text.data() + text.size(), value);
  if (text.empty() || ec != std::errc{} || end != text.data() + text.size() ||
      value < 0 || value > 3) {
    return std::nullopt;
  }
  return value;
}

SecurityVerdict AwsCliVerifier::verify_ptrace_policy() const {
  if (options_.min_ptrace_scope <= 0) {
    return SecurityVerdict(std::errc{}, "ok");
  }
  if (!options_.ptrace_waiver_file.empty() &&
      Security::trusted_file(options_.ptrace_waiver_file)) {
    SPDLOG_TRACE("aws ptrace_scope requirement waived by root-owned file");
    return SecurityVerdict(std::errc{}, "ok");
  }
  std::ifstream file(options_.ptrace_scope_file);
  std::string text;
  if (!file || !std::getline(file, text)) {
    return SecurityVerdict(
        std::errc::permission_denied,
        "Yama ptrace_scope is unavailable (see docs/aws.md)");
  }
  const auto scope = parse_ptrace_scope(text);
  if (!scope) {
    return SecurityVerdict(std::errc::permission_denied,
                           "Yama ptrace_scope is unreadable (see docs/aws.md)");
  }
  if (*scope < options_.min_ptrace_scope) {
    return SecurityVerdict(
        std::errc::permission_denied,
        "Yama ptrace_scope is too low: a same-user parent could "
        "attach to the AWS CLI (see docs/aws.md)");
  }
  return SecurityVerdict(std::errc{}, "ok");
}

namespace {

// Value of the "Key: value" line `key` (including its colon) in a
// /proc/<pid>/status or fdinfo style text.
std::optional<std::string_view> proc_field(std::string_view text,
                                           std::string_view key) {
  while (!text.empty()) {
    const auto line = strutil::next_line(text);
    if (line.starts_with(key)) {
      return strutil::trim(line.substr(key.size()));
    }
  }
  return std::nullopt;
}

template <typename Int>
std::optional<Int> parse_int(std::string_view text, int base = 10) {
  Int value{};
  const auto [end, ec] =
      std::from_chars(text.data(), text.data() + text.size(), value, base);
  if (ec != std::errc{} || end != text.data() + text.size()) {
    return std::nullopt;
  }
  return value;
}

// Whether a /proc/<pid>/fdinfo/<fd> text describes a descriptor that can read
// (opened O_RDONLY or O_RDWR, and not a mere O_PATH reference).
bool opened_for_reading(std::string_view fdinfo) {
  const auto flags = proc_field(fdinfo, "flags:");
  const auto mode = flags ? parse_int<long>(*flags, 8) : std::nullopt;
  return mode && (*mode & O_PATH) == 0 &&
         ((*mode & O_ACCMODE) == O_RDONLY || (*mode & O_ACCMODE) == O_RDWR);
}

// Whether `pid` holds a descriptor that can read the pipe `out`.
bool holds_pipe_read_end(pid_t pid, const struct stat &out,
                         std::error_code &ec) {
  std::filesystem::directory_iterator it(proc_link(pid, "fd"), ec);
  for (const std::filesystem::directory_iterator end; !ec && it != end;
       it.increment(ec)) {
    struct stat peer{};
    if (::stat(it->path().c_str(), &peer) != 0 || !S_ISFIFO(peer.st_mode) ||
        !same_file(peer, out)) {
      continue;
    }
    const auto info = ProcessInfo::readProc(
        pid, ("fdinfo/" + it->path().filename().string()).c_str(),
        kMaxFdInfoBytes);
    if (info && opened_for_reading(*info)) {
      return true;
    }
  }
  return false;
}

// A /proc entry name that is a process id; nullopt for everything else.
std::optional<pid_t> pid_from_proc_entry(const std::string &name) {
  const auto pid = parse_int<pid_t>(name);
  return pid && *pid > 0 ? pid : std::nullopt;
}

} // namespace

SecurityVerdict AwsCliVerifier::verify_output_channel(pid_t caller, int fd) {
  struct stat out{};
  if (::fstat(fd, &out) != 0 || !S_ISFIFO(out.st_mode)) {
    return SecurityVerdict(std::errc::permission_denied,
                           "stdout must be a pipe from the AWS CLI");
  }

  std::error_code ec;
  if (!holds_pipe_read_end(caller, out, ec)) {
    if (ec) {
      return SecurityVerdict(std::errc::io_error,
                             "cannot inspect caller file descriptors");
    }
    return SecurityVerdict(std::errc::permission_denied,
                           "stdout is not a pipe read by the AWS CLI");
  }

  // /proc can hide processes or descriptors from this user. A scan can
  // reject visible readers, but cannot prove current or future exclusivity.
  std::filesystem::directory_iterator proc("/proc", ec);
  for (const std::filesystem::directory_iterator end; !ec && proc != end;
       proc.increment(ec)) {
    const auto pid = pid_from_proc_entry(proc->path().filename().string());
    if (!pid || *pid == caller) {
      continue;
    }
    std::error_code peer_ec;
    if (holds_pipe_read_end(*pid, out, peer_ec)) {
      return SecurityVerdict(std::errc::permission_denied,
                             "another process holds a read end of stdout");
    }
  }
  if (ec) {
    return SecurityVerdict(std::errc::io_error,
                           "cannot scan /proc for pipe readers");
  }
  return SecurityVerdict(std::errc{}, "ok");
}

std::optional<std::vector<std::string>>
AwsCliVerifier::parse_pin_file(std::string_view text) {
  std::vector<std::string> digests;
  while (!text.empty()) {
    const std::string_view line = strutil::trim(strutil::next_line(text));
    if (line.empty() || line.front() == '#') {
      continue;
    }

    const auto space = line.find_first_of(" \t");
    const std::string_view digest = line.substr(0, space);
    if (!is_hex_digest(digest)) {
      return std::nullopt;
    }
    digests.push_back(strutil::ascii_lower(digest));
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

  const auto status =
      read_chunks(fd, [&state](const char *chunk, std::size_t n) {
        crypto_hash_sha256_update(
            &state, reinterpret_cast<const unsigned char *>(chunk),
            static_cast<unsigned long long>(n));
        return true;
      });
  if (status != ReadStatus::ok) {
    return std::nullopt;
  }

  std::array<unsigned char, crypto_hash_sha256_BYTES> digest;
  crypto_hash_sha256_final(&state, digest.data());
  char hex[crypto_hash_sha256_BYTES * 2 + 1];
  ::sodium_bin2hex(hex, sizeof(hex), digest.data(), digest.size());
  return std::string(hex);
}

namespace {

// What verify() learns about the caller's executable before trusting any of
// the rest of its state.
struct CallerImage {
  struct stat running{}; // identity of the running image, by inode
  std::string exe_link;  // /proc/<pid>/exe
  std::filesystem::path link_target;
  // Directory the official bundle's bootloader exports as LD_LIBRARY_PATH;
  // empty for any other layout.
  std::string bundle_library_path;
};

SecurityVerdict verify_not_traced(pid_t pid) {
  // Snapshot only: this check cannot prevent a later ptrace attachment.
  const auto status = ProcessInfo::readProc(pid, "status");
  if (!status) {
    return SecurityVerdict(std::errc::io_error, "cannot read caller status");
  }
  const auto field = proc_field(*status, "TracerPid:");
  const auto tracer = field ? parse_int<long>(*field) : std::nullopt;
  if (!tracer) {
    return SecurityVerdict(std::errc::io_error,
                           "caller status lacks TracerPid");
  }
  if (*tracer != 0) {
    return SecurityVerdict(std::errc::permission_denied,
                           "caller is being traced");
  }
  return SecurityVerdict(std::errc{}, "ok");
}

SecurityVerdict inspect_caller_executable(pid_t pid, CallerImage &caller) {
  caller.exe_link = proc_link(pid, "exe");
  if (::stat(caller.exe_link.c_str(), &caller.running) != 0) {
    return SecurityVerdict(std::errc::io_error,
                           "cannot inspect caller executable");
  }
  std::error_code ec;
  caller.link_target = std::filesystem::read_symlink(caller.exe_link, ec);
  if (ec) {
    return SecurityVerdict(std::errc::io_error,
                           "cannot read caller executable link");
  }
  if (caller.link_target.string().ends_with(" (deleted)")) {
    return SecurityVerdict(std::errc::permission_denied,
                           "caller executable was replaced on disk");
  }
  return SecurityVerdict(std::errc{}, "ok");
}

// The running image must be one of the trusted AWS CLI installations.
SecurityVerdict match_installation(const AwsCliVerifier::Options &options,
                                   const TrustPolicy &install_trust,
                                   CallerImage &caller) {
  bool any_trusted = false;
  for (const auto &candidate : options.candidates) {
    const auto trusted = Security::trusted_executable(candidate, install_trust);
    if (!trusted || trusted->filename() != options.required_name) {
      continue;
    }
    any_trusted = true;
    struct stat expected{};
    if (::stat(trusted->c_str(), &expected) != 0 ||
        !same_file(caller.running, expected)) {
      continue;
    }
    const bool official_bundle =
        candidate == std::filesystem::path(kServiceBundle) ||
        candidate == std::filesystem::path(kRootBundle);
    // The official Linux onedir bundle uses contents_directory='.'; its
    // bootloader sets LD_LIBRARY_PATH to the actual executable directory.
    if (official_bundle && *trusted == caller.link_target) {
      caller.bundle_library_path = trusted->parent_path().string();
    }
    return SecurityVerdict(std::errc{}, "ok");
  }
  if (!any_trusted) {
    return SecurityVerdict(std::errc::io_error,
                           "no trusted AWS CLI v2 installation found");
  }
  return SecurityVerdict(std::errc::permission_denied,
                         "caller is not a trusted AWS CLI v2");
}

// Optional digest pin of the running image. No pin file means no pinning.
SecurityVerdict verify_pin(const std::filesystem::path &pin_file,
                           const std::string &exe_link) {
  using Status = TrustedFileContent::Status;
  const TrustedFileContent file =
      Security::read_trusted_file(pin_file, kMaxPinBytes);
  switch (file.status) {
  case Status::ok:
    break;
  case Status::absent:
    return SecurityVerdict(std::errc{}, "ok");
  case Status::cannot_inspect:
    return SecurityVerdict(std::errc::io_error,
                           "cannot inspect AWS CLI pin file");
  case Status::untrusted:
    return SecurityVerdict(std::errc::io_error,
                           "AWS CLI pin file is not root-owned");
  case Status::cannot_open:
    return SecurityVerdict(std::errc::io_error, "cannot open AWS CLI pin file");
  case Status::cannot_read:
    return SecurityVerdict(std::errc::io_error, "cannot read AWS CLI pin file");
  case Status::too_large:
    return SecurityVerdict(std::errc::io_error,
                           "AWS CLI pin file is too large");
  }

  const auto pins = AwsCliVerifier::parse_pin_file(file.data);
  if (!pins) {
    return SecurityVerdict(std::errc::io_error,
                           "AWS CLI pin file is empty or invalid");
  }
  const UniqueFd exe(::open(exe_link.c_str(), O_RDONLY | O_CLOEXEC));
  if (!exe.valid()) {
    return SecurityVerdict(std::errc::io_error,
                           "cannot open caller executable");
  }
  const auto digest = AwsCliVerifier::sha256_hex(exe.get());
  if (!digest) {
    return SecurityVerdict(std::errc::io_error,
                           "cannot hash caller executable");
  }
  if (std::find(pins->begin(), pins->end(), *digest) == pins->end()) {
    return SecurityVerdict(
        std::errc::permission_denied,
        "AWS CLI does not match its pinned SHA-256 (modified or "
        "upgraded without refreshing the pin)");
  }
  return SecurityVerdict(std::errc{}, "ok");
}

SecurityVerdict verify_arguments(pid_t pid) {
  const auto args = ProcessInfo::argv(pid);
  if (!args) {
    return SecurityVerdict(std::errc::io_error, "cannot read caller arguments");
  }
  if (const auto bad = AwsCliVerifier::forbidden_arguments(*args)) {
    SPDLOG_TRACE("aws caller argument not allowed: {}", *bad);
    return SecurityVerdict(std::errc::permission_denied,
                           "AWS CLI argument not allowed");
  }
  return SecurityVerdict(std::errc{}, "ok");
}

// Environment and configuration the CLI started with.
SecurityVerdict verify_launch_context(pid_t pid,
                                      std::string_view bundle_library_path) {
  const auto environment =
      ProcessInfo::readProc(pid, "environ", kMaxEnvironBytes);
  if (!environment) {
    return SecurityVerdict(std::errc::io_error,
                           "cannot read caller environment");
  }
  if (!same_proc_object(pid, "root") || !same_proc_object(pid, "ns/mnt")) {
    return SecurityVerdict(std::errc::io_error,
                           "cannot verify caller filesystem context");
  }
  if (const auto bad = AwsCliVerifier::forbidden_environment(
          *environment, bundle_library_path)) {
    SPDLOG_TRACE("aws caller environment variable not allowed: {}", *bad);
    return SecurityVerdict(std::errc::permission_denied,
                           "AWS CLI environment variable not allowed");
  }
  return verify_cli_config(*environment);
}

// Executable memory must come from trusted files, apart from what an explicit
// root-owned waiver allows.
SecurityVerdict verify_memory_maps(pid_t pid,
                                   const AwsCliVerifier::Options &options,
                                   const TrustPolicy &install_trust) {
  const auto maps = ProcessInfo::readProc(pid, "maps", kMaxMapsBytes);
  if (!maps) {
    return SecurityVerdict(std::errc::io_error,
                           "cannot read caller memory map");
  }
  const auto mapping = AwsCliVerifier::unsafe_mapping(*maps);
  if (mapping == AwsCliVerifier::UnsafeMapping::file_writable_executable) {
    return SecurityVerdict(std::errc::permission_denied,
                           "AWS CLI has a writable executable file mapping");
  }
  if (mapping != AwsCliVerifier::UnsafeMapping::none) {
    if (!options.anonymous_exec_waiver_file.empty() &&
        Security::trusted_file(options.anonymous_exec_waiver_file)) {
      SPDLOG_TRACE("aws anonymous executable memory waived by root-owned file");
    } else if (mapping ==
               AwsCliVerifier::UnsafeMapping::anonymous_writable_executable) {
      return SecurityVerdict(
          std::errc::permission_denied,
          "AWS CLI has writable executable memory (see docs/aws.md)");
    } else {
      return SecurityVerdict(
          std::errc::permission_denied,
          "AWS CLI has anonymous executable memory (see docs/aws.md)");
    }
  }
  for (const auto &path : AwsCliVerifier::executable_mapping_paths(*maps)) {
    if (allowed_special_mapping(path)) {
      continue;
    }
    if (!Security::trusted_file(path, install_trust)) {
      SPDLOG_TRACE("aws caller has untrusted code mapped: {}", path);
      return SecurityVerdict(std::errc::permission_denied,
                             "AWS CLI has untrusted code mapped");
    }
  }
  return SecurityVerdict(std::errc{}, "ok");
}

} // namespace

SecurityVerdict AwsCliVerifier::verify(pid_t pid) const {
  if (pid <= 1) {
    return SecurityVerdict(std::errc::io_error, "no AWS CLI parent process");
  }
  const TrustPolicy install_trust{options_.install_owners};
  CallerImage caller;

  // The order matters: cheap identity checks first, then everything read from
  // the caller's /proc entries, then the final "still the same process" check.
  if (const auto v = verify_ptrace_policy(); !v.passed()) {
    return v;
  }
  if (const auto v = verify_not_traced(pid); !v.passed()) {
    return v;
  }
  if (const auto v = inspect_caller_executable(pid, caller); !v.passed()) {
    return v;
  }
  if (const auto v = match_installation(options_, install_trust, caller);
      !v.passed()) {
    return v;
  }
  if (const auto v = verify_pin(options_.pin_file, caller.exe_link);
      !v.passed()) {
    return v;
  }
  if (const auto v = verify_arguments(pid); !v.passed()) {
    return v;
  }
  if (const auto v = verify_launch_context(pid, caller.bundle_library_path);
      !v.passed()) {
    return v;
  }
  if (const auto v = verify_memory_maps(pid, options_, install_trust);
      !v.passed()) {
    return v;
  }

  // The caller must still be the same process we started inspecting.
  struct stat after{};
  if (::stat(caller.exe_link.c_str(), &after) != 0 ||
      !same_file(caller.running, after)) {
    return SecurityVerdict(std::errc::io_error,
                           "caller changed during verification");
  }
  return SecurityVerdict(std::errc{}, "ok");
}

} // namespace methuselah
