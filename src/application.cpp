#include "config.h"

#include "methuselah/application.hpp"

#include "methuselah/aws_cli_verifier.hpp"
#include "methuselah/aws_credentials.hpp"
#include "methuselah/aws_signers.hpp"
#include "methuselah/config.hpp"
#include "methuselah/fd_io.hpp"
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

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

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

// Loads the user's configuration. On failure, says why on stderr and returns
// nullopt.
std::optional<Config> load_config(const std::filesystem::path &config_path) {
  if (!std::filesystem::exists(config_path)) {
    std::cerr << "ERROR(configuration): config path is missing on "
              << config_path.string() << std::endl;
    return std::nullopt;
  }
  SPDLOG_TRACE("config path OK: {}", config_path.string());

  try {
    return Config::load(config_path);
  } catch (const std::exception &ex) {
    std::cerr << "Failed to parse config file: " << ex.what() << '\n';
    return std::nullopt;
  }
}

// The interactive flows leave their prompt loop on SIGINT/SIGTERM; note it.
void log_if_signalled() {
  if (SignalGuard::received()) {
    SPDLOG_TRACE("application received signal {}, cleaning up...",
                 SignalGuard::signum());
  }
}

int run_git_flow(const GitPredicate &predicate) {
  const std::filesystem::path config_path = resolve_path(kConfigFile);
  const auto config_file = load_config(config_path);
  if (!config_file) {
    return EXIT_FAILURE;
  }
  const Config &config = *config_file;

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

  log_if_signalled();

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

  log_if_signalled();

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

  log_if_signalled();

  return EXIT_SUCCESS;
}

// Every macro verifies its caller the same way. Returns true when the caller
// passed; otherwise says why on stderr and returns false.
bool caller_verified(const char *macro, const SecurityVerdict &verdict) {
  if (verdict.passed()) {
    return true;
  }
  std::cerr << "Error: " << macro << " macro security verification "
            << (verdict.result == std::errc::permission_denied ? "failure"
                                                               : "faulted")
            << ": " << verdict.reason << std::endl;
  return false;
}

// Anyone who can replace the encrypted file can encrypt their own keys to the
// user's public key and make the AWS CLI talk to their account instead.
bool credential_file_is_private(int fd) {
  struct stat info{};
  return ::fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
         info.st_uid == ::getuid() && (info.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

std::optional<std::filesystem::path> aws_gpg_path(const std::string &profile) {
  const std::filesystem::path config_path = resolve_path(kConfigFile);
  const auto config = load_config(config_path);
  if (!config) {
    return std::nullopt;
  }

  const std::string section = "aws:" + profile;
  const auto gpg_file = config->gpg_file_for(section);
  if (!gpg_file) {
    std::cerr << "ERROR(configuration): no [" << section << "] gpgfile in "
              << config_path.string() << std::endl;
    return std::nullopt;
  }
  // Keep the final component intact so open() can reject a symlink.
  return resolve_path(*gpg_file, false);
}

// Longest a passphrase prompt may stay open in total. Waiting callers give up
// after InstanceLock's longer limit, so an abandoned dialog cannot wedge them.
constexpr int kUnlockBudgetSeconds = 120;

// What unlock_credentials() is asked to unlock. The caller owns what is being
// unlocked, so it supplies the dialog title, as the other flows do.
struct UnlockRequest {
  int fd;                            // encrypted file, rewound per attempt
  const std::filesystem::path &file; // only used in messages
  std::string_view required_signer;  // empty: no signature required
  std::string_view title;            // passphrase dialog title
};

// Reuses an unlocked gpg-agent when possible, otherwise asks for the
// passphrase. Unlike the git flow, cancelling is a failure: the CLI must not
// see an empty, "successful" reply.
std::optional<DecryptResult> unlock_credentials(const GpgDecryptor &decryptor,
                                                const UnlockRequest &request) {
  auto remembered =
      decryptor.decrypt_fd(request.fd, SecureString{}, request.required_signer);
  if (remembered.ok()) {
    return remembered;
  }
  if (remembered.not_signed()) {
    std::cerr << "ERROR: " << request.file << ": " << remembered.error()
              << std::endl;
    return std::nullopt;
  }

  UiSession::install_log_callback();
  UiSession ui;
  if (!ui.ready()) {
    return std::nullopt;
  }

  PromptOptions options;
  options.title = std::string(request.title);
  options.message = kDefaultMessage;

  const auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds(kUnlockBudgetSeconds);
  while (!SignalGuard::received()) {
    const auto remaining = deadline - std::chrono::steady_clock::now();
    if (remaining <= std::chrono::steady_clock::duration::zero()) {
      break;
    }
    options.timeout_seconds = static_cast<int>(
        std::chrono::ceil<std::chrono::seconds>(remaining).count());
    std::optional<SecureString> password = ui.prompt_password(options);
    if (!password) {
      break;
    }
    auto result =
        decryptor.decrypt_fd(request.fd, *password, request.required_signer);
    secure_clear(*password);
    if (result.ok()) {
      return result;
    }
    std::cerr << "ERROR: credential decryption issue on " << request.file
              << ": " << result.error() << std::endl;
    if (result.not_signed()) {
      break;
    }
  }
  return std::nullopt;
}

// The passphrase prompt can stay open for a long time. Make sure the process
// that is about to receive the secrets is still the verified AWS CLI.
bool caller_still_trusted(pid_t caller, const Security &security) {
  if (ProcessInfo::parent() != caller) {
    std::cerr << "Error: aws caller changed while unlocking credentials"
              << std::endl;
    return false;
  }
  return caller_verified("aws", security.verify_aws(caller)) &&
         caller_verified("aws", AwsCliVerifier::verify_output_channel(
                                    caller, STDOUT_FILENO));
}

int run_aws_flow(const std::string &profile, pid_t caller,
                 const Security &security) {
  if (!AwsSigners::valid_profile_name(profile)) {
    std::cerr << "Error: invalid aws profile name" << std::endl;
    return EXIT_FAILURE;
  }

  // Check that the verified CLI holds a read end and that no other reader
  // is visible in /proc at this point. This cannot guarantee exclusive access.
  if (!caller_verified("aws", AwsCliVerifier::verify_output_channel(
                                  caller, STDOUT_FILENO))) {
    return EXIT_FAILURE;
  }

  const auto signer = AwsSigners::load(AwsSigners::default_file(), profile);
  if (!signer.passed()) {
    std::cerr << "Error: " << signer.reason << std::endl;
    return EXIT_FAILURE;
  }

  const auto gpg_path = aws_gpg_path(profile);
  if (!gpg_path) {
    return EXIT_FAILURE;
  }
  const UniqueFd file(::open(gpg_path->c_str(),
                             O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
  if (!credential_file_is_private(file.get()) ||
      ::fcntl(file.get(), F_SETFL, 0) == -1) {
    std::cerr << "Error: " << gpg_path->string()
              << " must be a regular file owned by you and not writable by "
                 "group or others"
              << std::endl;
    return EXIT_FAILURE;
  }

  GpgDecryptor decryptor;
  auto unlocked =
      unlock_credentials(decryptor, {file.get(), *gpg_path, signer.fingerprint,
                                     "aws credentials"});
  if (!unlocked) {
    std::cerr << "Error: could not unlock aws credentials for profile "
              << profile << std::endl;
    return EXIT_FAILURE;
  }

  const auto [ec, reason, credentials] =
      AwsCredentials::parse(unlocked->plaintext());
  if (ec != std::errc{}) {
    std::cerr << "Error: " << reason << std::endl;
    return EXIT_FAILURE;
  }

  if (!caller_still_trusted(caller, security) || SignalGuard::received()) {
    return EXIT_FAILURE;
  }

  SecureString json = credentials.to_credential_process_json();
  std::cout.flush();
  const bool written = secure_write(STDOUT_FILENO, json);
  secure_clear(json);
  return written ? EXIT_SUCCESS : EXIT_FAILURE;
}

// One entry point per macro: verify the caller, then run the flow.
int run_gpg_macro(const Security &security) {
  SPDLOG_TRACE("gpg security verification...");
  const auto verdict = security.verify_gpg();

  SPDLOG_TRACE("gpg security verification result");
  if (!caller_verified("gpg", verdict)) {
    return EXIT_FAILURE;
  }

  PinentryServer server("gpg credentials", kDefaultMessage);
  return server.run();
}

int run_git_macro(int argc, char **argv, const Security &security) {
  // Git also invokes helpers for "store" and "erase"; only "get" is served.
  if (argc < 3 || std::strcmp(argv[2], "get") != 0) {
    return EXIT_SUCCESS;
  }
  if (!caller_verified("git", security.verify_git())) {
    return EXIT_FAILURE;
  }
  return run_git_flow(GitPredicate::read_from_stdin());
}

int run_aws_macro(int argc, char **argv, const Security &security) {
  const pid_t caller = ProcessInfo::parent();
  if (!caller_verified("aws", security.verify_aws(caller))) {
    return EXIT_FAILURE;
  }
  const std::string profile = argc >= 3 ? argv[2] : "default";
  return run_aws_flow(profile, caller, security);
}

int run_ssh_macro(const Security &security) {
  if (!caller_verified("ssh", security.verify_ssh())) {
    return EXIT_FAILURE;
  }
  return run_ssh_flow();
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
    if (macro == Macro::Aws) {
      std::cerr << "Error: could not take the credential_process lock "
                   "(another request is still waiting for a passphrase)"
                << std::endl;
      return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
  }

  switch (macro) {
  case Macro::Gpg:
    return run_gpg_macro(security);
  case Macro::Git:
    return run_git_macro(argc, argv, security);
  case Macro::Aws:
    return run_aws_macro(argc, argv, security);
  case Macro::Dummy:
    return run_dummy();
  case Macro::Ssh:
    return run_ssh_macro(security);
  case Macro::Unknown:
    break; // rejected above, before the lock was taken
  }
  return EXIT_FAILURE;
}

void Application::version() {
  std::cout << PROJECT_NAME << " " << PROJECT_VERSION << std::endl;
}

} // namespace methuselah
