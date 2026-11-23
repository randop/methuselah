#include "config.h"

#include "methuselah/application.hpp"

#include "methuselah/aws_credentials.hpp"
#include "methuselah/config.hpp"
#include "methuselah/git_credentials.hpp"
#include "methuselah/gpg_decrypt.hpp"
#include "methuselah/instance_lock.hpp"
#include "methuselah/logging.hpp"
#include "methuselah/macro.hpp"
#include "methuselah/path.hpp"
#include "methuselah/pinentry_server.hpp"
#include "methuselah/process_info.hpp"
#include "methuselah/secure_memory.hpp"
#include "methuselah/security.hpp"
#include "methuselah/signal_guard.hpp"
#include "methuselah/ui_session.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace methuselah {
namespace {

constexpr const char kDefaultMessage[] =
    "Enter the passphrase to     \nunlock your credentials.     ";

constexpr const char kConfigFile[] = "$HOME/.config/pinentry.methuselah";

Macro parse_macro(int argc, char **argv) {
  if (argc < 2) {
    return Macro::Unknown;
  }

  const std::string_view flag{argv[1]};
  if (flag == "--macro=git") {
    SPDLOG_TRACE("macro: git");
    return Macro::Git;
  } else if (flag == "--macro=gpg") {
    SPDLOG_TRACE("macro: gpg");
    return Macro::Gpg;
  } else if (flag == "--macro=dummy") {
    SPDLOG_TRACE("macro: dummy");
    return Macro::Dummy;
  } else if (flag == "--macro=ssh") {
    SPDLOG_TRACE("macro: ssh");
    return Macro::Ssh;
  } else if (flag == "--macro=aws") {
    SPDLOG_TRACE("macro: aws");
    return Macro::Aws;
  }
  return Macro::Unknown;
}

int run_git_flow(const GitPredicate &predicate) {
  const std::filesystem::path config_path = resolve_path(kConfigFile);

  if (std::filesystem::exists(config_path)) {
    SPDLOG_TRACE("config path OK: {}", config_path.string());
  } else {
    std::cerr << "ERROR(configuration): config path is missing on "
              << config_path.string() << std::endl;
    return EXIT_FAILURE;
  }

  Config config;
  try {
    config = Config::load(config_path);
  } catch (const std::exception &ex) {
    std::cerr << "Failed to parse config file: " << ex.what() << '\n';
    return EXIT_FAILURE;
  }

  const auto gpg_file = config.gpg_file_for(predicate.host());
  if (!gpg_file) {
    std::cerr << "ERROR(configuration): Missing gpg file on "
              << config_path.string() << std::endl;
    return EXIT_FAILURE;
  }

  const std::filesystem::path gpg_path = resolve_path(*gpg_file);

  SPDLOG_TRACE("git username: {}", predicate.username());
  SPDLOG_TRACE("git gpgfile: {}", gpg_path.string());

  if (std::filesystem::exists(gpg_path)) {
    SPDLOG_TRACE("gpg: OK");
  } else {
    return EXIT_FAILURE;
  }

  GpgDecryptor decryptor;
  auto remembered = decryptor.decrypt_file(gpg_path, SecureString{});
  if (remembered.ok()) {
    predicate.write_credentials(remembered.plaintext());
    return EXIT_SUCCESS;
  }

  UiSession::install_log_callback();
  UiSession ui;
  if (!ui.ready()) {
    return EXIT_FAILURE;
  }

  PromptOptions options;
  options.title = "git credentials";
  options.message = kDefaultMessage;

  while (!SignalGuard::received()) {
    std::optional<SecureString> password = ui.prompt_password(options);
    if (!password) {
      break;
    }

    auto decrypt_result = decryptor.decrypt_file(gpg_path, *password);
    secure_clear(*password);

    if (decrypt_result.ok()) {
      predicate.write_credentials(decrypt_result.plaintext());
      break;
    }

    std::cerr << "ERROR: credential decryption issue on " << gpg_path << ": "
              << decrypt_result.error() << std::endl;
  }

  if (SignalGuard::received()) {
    SPDLOG_TRACE("application received signal {}, cleaning up...",
                 SignalGuard::signum());
  }

  return EXIT_SUCCESS;
}

int run_dummy() {
  UiSession::install_debug_callback();
  UiSession ui;
  if (!ui.ready()) {
    return EXIT_FAILURE;
  }

  PromptOptions options;
  options.title = "dummy";
  options.message = kDefaultMessage;

  while (!SignalGuard::received()) {
    std::optional<SecureString> password = ui.prompt_password(options);
    if (!password) {
      break;
    }
  }

  if (SignalGuard::received()) {
    SPDLOG_TRACE("application received signal {}, cleaning up...",
                 SignalGuard::signum());
  }

  return EXIT_SUCCESS;
}

int run_ssh_flow() {
  UiSession::install_log_callback();
  UiSession ui;
  if (!ui.ready()) {
    return EXIT_FAILURE;
  }

  PromptOptions options;
  options.title = "ssh agent";
  options.message = kDefaultMessage;

  while (!SignalGuard::received()) {
    std::optional<SecureString> password = ui.prompt_password(options);
    if (!password) {
      break;
    }
    password->push_back('\n');
    const bool written = secure_write(STDOUT_FILENO, *password);
    secure_clear(*password);
    if (!written) {
      return EXIT_FAILURE;
    }
    break;
  }

  if (SignalGuard::received()) {
    SPDLOG_TRACE("application received signal {}, cleaning up...",
                 SignalGuard::signum());
  }

  return EXIT_SUCCESS;
}

// Every macro verifies its caller the same way. Returns true, after saying
// why, when the caller must be refused.
bool reject_unverified(const char *macro, const SecurityVerdict &verdict) {
  if (verdict.passed()) {
    return false;
  }
  std::cerr << "Error: " << macro << " macro security verification "
            << (verdict.result == SecurityVerificationResult::failed
                    ? "failure"
                    : "faulted")
            << ": " << verdict.reason << std::endl;
  return true;
}

bool valid_profile_name(std::string_view name) {
  return !name.empty() && name.size() <= 64 &&
         std::all_of(name.begin(), name.end(), [](unsigned char c) {
           return std::isalnum(c) != 0 || c == '_' || c == '-' || c == '.' ||
                  c == '@';
         });
}

class CredentialFile {
public:
  explicit CredentialFile(const std::filesystem::path &path)
      : fd_(::open(path.c_str(),
                   O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)) {}
  ~CredentialFile() {
    if (fd_ >= 0) {
      ::close(fd_);
    }
  }
  CredentialFile(const CredentialFile &) = delete;
  CredentialFile &operator=(const CredentialFile &) = delete;
  [[nodiscard]] int get() const { return fd_; }

private:
  int fd_;
};

// Anyone who can replace the encrypted file can encrypt their own keys to the
// user's public key and make the AWS CLI talk to their account instead.
bool credential_file_is_private(int fd) {
  struct stat info{};
  return ::fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
         info.st_uid == ::getuid() && (info.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

std::optional<std::filesystem::path> aws_gpg_path(const std::string &profile) {
  const std::filesystem::path config_path = resolve_path(kConfigFile);
  if (!std::filesystem::exists(config_path)) {
    std::cerr << "ERROR(configuration): config path is missing on "
              << config_path.string() << std::endl;
    return std::nullopt;
  }

  Config config;
  try {
    config = Config::load(config_path);
  } catch (const std::exception &ex) {
    std::cerr << "Failed to parse config file: " << ex.what() << '\n';
    return std::nullopt;
  }

  const std::string section = "aws:" + profile;
  const auto gpg_file = config.gpg_file_for(section);
  if (!gpg_file) {
    std::cerr << "ERROR(configuration): no [" << section << "] gpgfile in "
              << config_path.string() << std::endl;
    return std::nullopt;
  }
  // Keep the final component intact so open() can reject a symlink.
  return resolve_path(*gpg_file, false);
}

// Reuses an unlocked gpg-agent when possible, otherwise asks for the
// passphrase. Unlike the git flow, cancelling is a failure: the CLI must not
// see an empty, "successful" reply.
std::optional<DecryptResult>
unlock_credentials(const GpgDecryptor &decryptor, int fd,
                   const std::filesystem::path &file) {
  auto remembered = decryptor.decrypt_fd(fd, SecureString{});
  if (remembered.ok()) {
    return remembered;
  }

  UiSession::install_log_callback();
  UiSession ui;
  if (!ui.ready()) {
    return std::nullopt;
  }

  PromptOptions options;
  options.title = "aws credentials";
  options.message = kDefaultMessage;

  while (!SignalGuard::received()) {
    std::optional<SecureString> password = ui.prompt_password(options);
    if (!password) {
      break;
    }
    auto result = decryptor.decrypt_fd(fd, *password);
    secure_clear(*password);
    if (result.ok()) {
      return result;
    }
    std::cerr << "ERROR: credential decryption issue on " << file << ": "
              << result.error() << std::endl;
  }
  return std::nullopt;
}

int run_aws_flow(const std::string &profile, pid_t caller,
                 const Security &security) {
  if (!valid_profile_name(profile)) {
    std::cerr << "Error: invalid aws profile name" << std::endl;
    return EXIT_FAILURE;
  }

  // credential_process output must go to the CLI's pipe, never a terminal or
  // a file where it would linger in scrollback or on disk.
  struct stat out{};
  if (::fstat(STDOUT_FILENO, &out) != 0 ||
      !(S_ISFIFO(out.st_mode) || S_ISSOCK(out.st_mode))) {
    std::cerr << "Error: stdout must be a pipe from the AWS CLI" << std::endl;
    return EXIT_FAILURE;
  }

  const auto gpg_path = aws_gpg_path(profile);
  if (!gpg_path) {
    return EXIT_FAILURE;
  }
  const CredentialFile file(*gpg_path);
  if (!credential_file_is_private(file.get()) ||
      ::fcntl(file.get(), F_SETFL, 0) == -1) {
    std::cerr << "Error: " << gpg_path->string()
              << " must be a regular file owned by you and not writable by "
                 "group or others"
              << std::endl;
    return EXIT_FAILURE;
  }

  GpgDecryptor decryptor;
  auto unlocked = unlock_credentials(decryptor, file.get(), *gpg_path);
  if (!unlocked) {
    std::cerr << "Error: could not unlock aws credentials for profile "
              << profile << std::endl;
    return EXIT_FAILURE;
  }

  std::string error;
  auto credentials = AwsCredentials::parse(unlocked->plaintext(), error);
  if (!credentials) {
    std::cerr << "Error: " << error << std::endl;
    return EXIT_FAILURE;
  }

  // The prompt can stay open for a long time. Make sure the process that is
  // about to receive the secrets is still the verified AWS CLI.
  if (ProcessInfo::parent() != caller) {
    std::cerr << "Error: aws caller changed while unlocking credentials"
              << std::endl;
    return EXIT_FAILURE;
  }
  if (reject_unverified("aws", security.verify_aws())) {
    return EXIT_FAILURE;
  }

  SecureString json = credentials->to_credential_process_json();
  std::cout.flush();
  const bool written = secure_write(STDOUT_FILENO, json);
  secure_clear(json);
  return written ? EXIT_SUCCESS : EXIT_FAILURE;
}

} // namespace

int Application::run(int argc, char **argv) {
  if (argc >= 2 && std::string_view{argv[1]} == "--version") {
    version();
    return EXIT_SUCCESS;
  }

  Logger logger;
  Security security;
  SignalGuard signals;

  const Macro macro = parse_macro(argc, argv);
  if (macro == Macro::Unknown) {
    std::cerr << "Error: unknown macro" << std::endl;
    return EXIT_FAILURE;
  }

  // credential_process callers queue behind each other and must never get an
  // empty "success"; the GUI macros keep the single-instance behaviour.
  InstanceLock lock(macro == Macro::Aws ? InstanceLock::Mode::wait
                                        : InstanceLock::Mode::focus_existing);
  if (!lock.acquired()) {
    return macro == Macro::Aws ? EXIT_FAILURE : EXIT_SUCCESS;
  }

  if (macro == Macro::Git && (argc < 3 || std::strcmp(argv[2], "get") != 0)) {
    return EXIT_SUCCESS;
  } else if (macro == Macro::Gpg) {
    SPDLOG_TRACE("gpg security verification...");
    const auto verdict = security.verify_gpg();

    SPDLOG_TRACE("gpg security verification result");
    if (reject_unverified("gpg", verdict)) {
      return EXIT_FAILURE;
    }

    PinentryServer server("gpg credentials", kDefaultMessage);
    return server.run();
  } else if (macro == Macro::Git) {
    if (reject_unverified("git", security.verify_git())) {
      return EXIT_FAILURE;
    }

    const GitPredicate predicate = GitPredicate::read_from_stdin();
    return run_git_flow(predicate);
  } else if (macro == Macro::Aws) {
    const pid_t caller = ProcessInfo::parent();
    if (reject_unverified("aws", security.verify_aws())) {
      return EXIT_FAILURE;
    }

    const std::string profile = argc >= 3 ? argv[2] : "default";
    return run_aws_flow(profile, caller, security);
  } else if (macro == Macro::Dummy) {
    return run_dummy();
  } else if (macro == Macro::Ssh) {
    if (reject_unverified("ssh", security.verify_ssh())) {
      return EXIT_FAILURE;
    }

    return run_ssh_flow();
  }
  return EXIT_FAILURE;
}

void Application::version() {
  std::cout << PROJECT_NAME << " " << PROJECT_VERSION << std::endl;
}

} // namespace methuselah
