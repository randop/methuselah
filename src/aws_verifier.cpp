#include "methuselah/aws_verifier.hpp"

#include "methuselah/process_info.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <set>
#include <string>
#include <string_view>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace methuselah {
namespace {

using Result = SecurityVerificationResult;
constexpr const char *kBundle = "/usr/local/aws-cli/v2/current/dist/aws";

AwsVerdict verdict(Result result, std::string reason) {
  return AwsVerdict{result, std::move(reason)};
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
constexpr std::array<std::string_view, 19> kForbiddenEnvironment = {
    "LD_*",              // loader injection: LD_PRELOAD, LD_LIBRARY_PATH, ...
    "PYTHON*",           // interpreter hooks: PYTHONPATH, PYTHONSTARTUP, ...
    "MALLOC_*",          // allocator hooks
    "GCONV_PATH",        // iconv module loading
    "LOCPATH",           // locale loading
    "NLSPATH",           // catalogue loading
    "HOSTALIASES",       // resolver redirection
    "AWS_ENDPOINT_URL*", // redirects every request, token included
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
constexpr std::array<std::string_view, 4> kForbiddenOptions = {
    "--endpoint-url", "--ca-bundle", "--no-verify-ssl", "--debug"};

bool name_matches(std::string_view name, std::string_view pattern) {
  if (!pattern.empty() && pattern.back() == '*') {
    return starts_with(name, pattern.substr(0, pattern.size() - 1));
  }
  return name == pattern;
}

bool is_hex_digest(std::string_view text) {
  return text.size() == 64 &&
         std::all_of(text.begin(), text.end(),
                     [](unsigned char c) { return std::isxdigit(c) != 0; });
}

bool same_file(const struct stat &a, const struct stat &b) {
  return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
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

AwsVerdict verify_plugin_config(std::string_view environment) {
  std::optional<std::string_view> home;
  while (!environment.empty()) {
    const auto entry = next_entry(environment);
    if (entry == "HOME" || starts_with(entry, "HOME=")) {
      if (home || entry == "HOME") {
        return verdict(Result::faulted, "cannot determine AWS CLI home");
      }
      home = entry.substr(5);
    }
  }
  if (!home || home->empty()) {
    return verdict(Result::faulted, "cannot determine AWS CLI home");
  }

  // The CLI caches full_config before invoking credential_process. Inspecting
  // a writable file now cannot tell us what the CLI loaded at startup.
  const auto trusted_home =
      Security::trusted_directory(std::filesystem::path(*home));
  if (!trusted_home) {
    return verdict(Result::failed, "AWS CLI home must be root controlled");
  }
  const auto config_dir = *trusted_home / ".aws";
  struct stat info{};
  if (::lstat(config_dir.c_str(), &info) != 0) {
    if (errno == ENOENT) {
      return verdict(Result::passed, "ok");
    }
    return verdict(Result::faulted, "cannot inspect AWS CLI config directory");
  }
  const auto trusted_dir = Security::trusted_directory(config_dir);
  if (!trusted_dir) {
    return verdict(Result::faulted,
                   "cannot establish trust in AWS CLI config directory");
  }
  const auto config = *trusted_dir / "config";
  if (::lstat(config.c_str(), &info) != 0) {
    return errno == ENOENT
               ? verdict(Result::passed, "ok")
               : verdict(Result::faulted, "cannot inspect AWS CLI config file");
  }
  const auto trusted_config = Security::trusted_file(config);
  if (!trusted_config) {
    return verdict(Result::faulted,
                   "cannot establish trust in AWS CLI config file");
  }

  // AWS CLI v2 looks up the exact top-level section "plugins" in full_config.
  // The shared credentials file only merges entries under "profiles".
  std::ifstream stream(*trusted_config);
  if (!stream) {
    return verdict(Result::faulted, "cannot read AWS CLI config file");
  }
  for (std::string line; std::getline(stream, line);) {
    if (line.find("[plugins]") != std::string::npos) {
      return verdict(Result::failed,
                     "AWS CLI plugin configuration is not allowed");
    }
  }
  if (stream.bad() || !stream.eof()) {
    return verdict(Result::faulted, "cannot read AWS CLI config file");
  }
  return verdict(Result::passed, "ok");
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

AwsCliVerifier::Options AwsCliVerifier::default_options() {
  Options options;
  options.candidates = {
      kBundle,
      "/usr/local/bin/aws",
      "/usr/bin/aws",
  };
  options.pin_file = "/etc/methuselah/aws-cli.sha256";
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
  // argv[0] is the program name; options after a bare "--" are positional.
  for (std::size_t i = 1; i < args.size(); ++i) {
    const std::string_view arg = args[i];
    if (arg == "--") {
      break;
    }
    // `aws configure export-credentials` prints the resolved credentials to
    // whoever started the CLI, defeating the point of the helper.
    if (arg == "export-credentials") {
      return args[i];
    }
    if (!starts_with(arg, "--")) {
      continue;
    }
    const std::string_view name = arg.substr(0, arg.find('='));
    for (const auto forbidden : kForbiddenOptions) {
      // argparse accepts unambiguous prefixes, so "--endpoint" must be
      // refused as well as "--endpoint-url". Require "--" plus one letter.
      if (name.size() >= 3 && starts_with(forbidden, name)) {
        return args[i];
      }
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
    std::string lowered(digest);
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                   [](unsigned char c) { return std::tolower(c); });
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

AwsVerdict AwsCliVerifier::verify(pid_t pid) const {
  if (pid <= 1) {
    return verdict(Result::faulted, "no AWS CLI parent process");
  }

  // Tracer: a same-uid debugger could rewrite the CLI after it passes.
  const auto status = ProcessInfo::readProc(pid, "status");
  if (!status) {
    return verdict(Result::faulted, "cannot read caller status");
  }
  const auto tracer = status->find("TracerPid:");
  if (tracer == std::string::npos) {
    return verdict(Result::faulted, "caller status lacks TracerPid");
  }
  if (std::atol(status->c_str() + tracer + 10) != 0) {
    return verdict(Result::failed, "caller is being traced");
  }

  // Identity of the running image, by inode.
  const std::string exeLink = proc_link(pid, "exe");
  struct stat running{};
  if (::stat(exeLink.c_str(), &running) != 0) {
    return verdict(Result::faulted, "cannot inspect caller executable");
  }
  std::error_code ec;
  const auto linkTarget = std::filesystem::read_symlink(exeLink, ec);
  if (ec) {
    return verdict(Result::faulted, "cannot read caller executable link");
  }
  if (linkTarget.string().ends_with(" (deleted)")) {
    return verdict(Result::failed, "caller executable was replaced on disk");
  }

  bool anyTrusted = false;
  bool matched = false;
  for (const auto &candidate : options_.candidates) {
    const auto trusted = Security::trusted_executable(candidate);
    if (!trusted || trusted->filename() != options_.required_name) {
      continue;
    }
    anyTrusted = true;
    struct stat expected{};
    if (::stat(trusted->c_str(), &expected) == 0 &&
        same_file(running, expected)) {
      matched = true;
      break;
    }
  }
  if (!anyTrusted) {
    return verdict(Result::faulted,
                   "no root-owned AWS CLI v2 installation found");
  }
  if (!matched) {
    return verdict(Result::failed, "caller is not a trusted AWS CLI v2");
  }

  // Optional digest pin of the running image.
  struct stat pinInfo{};
  if (::lstat(options_.pin_file.c_str(), &pinInfo) == 0) {
    const auto pinPath = Security::trusted_file(options_.pin_file);
    if (!pinPath) {
      return verdict(Result::faulted, "AWS CLI pin file is not root-owned");
    }
    const int pinFd = ::open(pinPath->c_str(), O_RDONLY | O_CLOEXEC);
    if (pinFd < 0) {
      return verdict(Result::faulted, "cannot open AWS CLI pin file");
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
      return verdict(Result::faulted, "AWS CLI pin file is empty or invalid");
    }

    const int exeFd = ::open(exeLink.c_str(), O_RDONLY | O_CLOEXEC);
    if (exeFd < 0) {
      return verdict(Result::faulted, "cannot open caller executable");
    }
    const auto digest = sha256_hex(exeFd);
    ::close(exeFd);
    if (!digest) {
      return verdict(Result::faulted, "cannot hash caller executable");
    }
    if (std::find(pins->begin(), pins->end(), *digest) == pins->end()) {
      return verdict(Result::failed,
                     "AWS CLI does not match its pinned SHA-256 (modified or "
                     "upgraded without refreshing the pin)");
    }
  } else if (errno != ENOENT) {
    return verdict(Result::faulted, "cannot inspect AWS CLI pin file");
  }

  const auto args = ProcessInfo::argv(pid);
  if (!args) {
    return verdict(Result::faulted, "cannot read caller arguments");
  }
  if (const auto bad = forbidden_arguments(*args)) {
    return verdict(Result::failed, "AWS CLI argument not allowed: " + *bad);
  }

  const auto environment = ProcessInfo::readProc(pid, "environ", 4U << 20);
  if (!environment) {
    return verdict(Result::faulted, "cannot read caller environment");
  }
  if (!same_proc_object(pid, "root") || !same_proc_object(pid, "ns/mnt")) {
    return verdict(Result::faulted, "cannot verify caller filesystem context");
  }
  // The official Linux onedir bundle uses contents_directory='.'; its
  // bootloader sets LD_LIBRARY_PATH to the actual executable directory.
  std::string bundle_library_path;
  if (const auto bundle = Security::trusted_executable(kBundle);
      bundle && *bundle == linkTarget) {
    bundle_library_path = bundle->parent_path().string();
  }
  if (const auto bad =
          forbidden_environment(*environment, bundle_library_path)) {
    return verdict(Result::failed,
                   "AWS CLI environment variable not allowed: " + *bad);
  }

  const auto plugin_config = verify_plugin_config(*environment);
  if (plugin_config.result != Result::passed) {
    return plugin_config;
  }

  const auto maps = ProcessInfo::readProc(pid, "maps", 16U << 20);
  if (!maps) {
    return verdict(Result::faulted, "cannot read caller memory map");
  }
  for (const auto &path : executable_mapping_paths(*maps)) {
    if (allowed_special_mapping(path)) {
      continue;
    }
    if (!Security::trusted_file(path)) {
      return verdict(Result::failed,
                     "AWS CLI has untrusted code mapped: " + path);
    }
  }

  // The caller must still be the same process we started inspecting.
  struct stat after{};
  if (::stat(exeLink.c_str(), &after) != 0 || !same_file(running, after)) {
    return verdict(Result::faulted, "caller changed during verification");
  }
  return verdict(Result::passed, "ok");
}

} // namespace methuselah
