#pragma once

#include "methuselah/security.hpp"

#include <sys/types.h>

#include <filesystem>
#include <iosfwd>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace methuselah {

// Decides whether the process that invoked `credential_process` is a genuine,
// untampered AWS CLI v2. Every check fails closed: anything that cannot be
// inspected is reported with `std::errc::io_error`, never as success.
//
//  1. The running image (/proc/<pid>/exe, by inode, so a path swapped after
//     exec cannot fool it) is an `aws` reached through a chain of components
//     owned by root or the `methuselah` service account, none of them writable
//     by group or others.
//  2. Optionally, its SHA-256 matches a root-owned pin list.
//  3. No tracer is reported when the caller's TracerPid is checked, and the
//     kernel's Yama ptrace_scope forbids a same-user parent from attaching
//     later (a root-owned waiver file can accept weaker systems).
//  4. Its argv does not redirect, weaken, or dump what it does with
//     credentials (--endpoint-url, --no-verify-ssl, --debug,
//     `configure export-credentials`, ...).
//  5. Its start-up environment carries no user-controlled loader, interpreter,
//     endpoint, or trust-store overrides.
//  6. Its CLI configuration files are root controlled, with no plugins
//     or auto-prompt activation.
//  7. Every executable file mapping is trusted, except libffi trampolines,
//     and no mapping is writable and executable or anonymous and executable.
//
// Threat model: this decides which *program* receives the credentials. It
// does not defend against a malicious process of the same user that can
// ptrace the AWS CLI; the Yama requirement above is what closes that door.
class AwsCliVerifier {
public:
  struct Options {
    // Install locations of the native AWS CLI v2 executable.
    std::vector<std::filesystem::path> candidates;
    // File name every resolved candidate must have (guards against an `aws`
    // symlink that resolves to an interpreter or shell).
    std::string required_name = "aws";
    // Optional root-owned list of allowed SHA-256 digests (sha256sum format).
    // Absent file: pinning is skipped. Present but unusable: verification
    // faults.
    std::filesystem::path pin_file;
    // UIDs allowed to own the CLI installation. Root is always accepted;
    // default_options() adds the unprivileged `methuselah` service account
    // when it exists. The calling user is never added.
    std::vector<uid_t> install_owners{0};
    // Smallest accepted Yama ptrace_scope (2: only CAP_SYS_PTRACE may attach).
    // Zero or less disables the check, for tests.
    int min_ptrace_scope = 2;
    std::filesystem::path ptrace_scope_file =
        "/proc/sys/kernel/yama/ptrace_scope";
    // When this file exists and passes the root-owned trust rules, a weaker
    // or missing ptrace_scope is accepted. Empty: no waiver.
    std::filesystem::path ptrace_waiver_file;
    // When this file exists and passes the root-owned trust rules, anonymous
    // executable memory is accepted (file-backed writable+executable never
    // is). Empty: no waiver.
    std::filesystem::path anonymous_exec_waiver_file;
  };

  [[nodiscard]] static Options default_options();

  AwsCliVerifier() : options_(default_options()) {}
  explicit AwsCliVerifier(Options options) : options_(std::move(options)) {}

  [[nodiscard]] SecurityVerdict verify(pid_t pid) const;

  // Confirms that `fd` is a pipe whose read end the verified caller holds, so
  // the credentials can only be read by that process.
  [[nodiscard]] static SecurityVerdict verify_output_channel(pid_t caller,
                                                             int fd);

  // Pure helpers, exposed for unit tests.

  // `environment` is the raw NUL-separated /proc/<pid>/environ. Returns the
  // offending variable name. Pass the official bundle's trusted directory
  // to allow its exact library path.
  [[nodiscard]] static std::optional<std::string>
  forbidden_environment(std::string_view environment,
                        std::string_view bundle_library_path = {});

  // Scans a trusted AWS config or credentials file for auto-prompt; only
  // the config file can supply plugins.
  [[nodiscard]] static SecurityVerdict scan_cli_config(std::istream &stream,
                                                       bool check_plugins);

  // Returns the offending argument.
  [[nodiscard]] static std::optional<std::string>
  forbidden_arguments(const std::vector<std::string> &args);

  // Paths of file-backed, executable mappings from /proc/<pid>/maps. A
  // trailing " (deleted)" is preserved so callers can reject it.
  [[nodiscard]] static std::vector<std::string>
  executable_mapping_paths(std::string_view maps);

  enum class UnsafeMapping {
    none,
    // A file mapping that is writable and executable: never legitimate.
    file_writable_executable,
    // Anonymous memory that is writable and executable, or executable at
    // all. Some libffi builds fall back to this for closures, so a root-owned
    // waiver file can accept it.
    anonymous_writable_executable,
    anonymous_executable,
  };

  // Inspects /proc/<pid>/maps for executable memory that no file vouches for
  // ([vdso], [vsyscall] and the libffi trampoline memfd are exempt).
  [[nodiscard]] static UnsafeMapping unsafe_mapping(std::string_view maps);

  // Parses the content of /proc/sys/kernel/yama/ptrace_scope (0 to 3).
  [[nodiscard]] static std::optional<int>
  parse_ptrace_scope(std::string_view text);

  // Parses sha256sum-style lines ("<64 hex>  <name>"), '#' comments and blank
  // lines allowed. Digests are returned lowercase. Any malformed line makes
  // the whole list invalid (nullopt), as does an empty list.
  [[nodiscard]] static std::optional<std::vector<std::string>>
  parse_pin_file(std::string_view text);

  // Lowercase hex SHA-256 of everything readable from `fd`.
  [[nodiscard]] static std::optional<std::string> sha256_hex(int fd);

private:
  [[nodiscard]] SecurityVerdict verify_ptrace_policy() const;

  Options options_;
};

} // namespace methuselah
