// Unit tests for the AWS credential_process helper: credential parsing, the
// AWS CLI caller verifier's pure checks, and verify() against real /proc
// state using throw-away child processes.
//
// Run with: meson test -C .build

#include "methuselah/aws_cli_verifier.hpp"
#include "methuselah/aws_credentials.hpp"
#include "methuselah/aws_signers.hpp"
#include "methuselah/fd_io.hpp"
#include "methuselah/gpg_decrypt.hpp"
#include "methuselah/process_info.hpp"
#include "methuselah/security.hpp"
#include "methuselah/text_util.hpp"

#include <sodium.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <type_traits>
#include <vector>

#include <fcntl.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace methuselah;

namespace {

int g_failures = 0;
int g_checks = 0;

#define CHECK(cond)                                                            \
  do {                                                                         \
    ++g_checks;                                                                \
    if (!(cond)) {                                                             \
      ++g_failures;                                                            \
      std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);     \
    }                                                                          \
  } while (0)

constexpr const char *kAccess = "AKIAIOSFODNN7EXAMPLE";
constexpr const char *kSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
constexpr const char *kToken =
    "FwoGZXIvYXdzEBYaDExampleSessionTokenValue0123456789+/=";
constexpr std::time_t kNow = 1795000000; // 2026-11-18, arbitrary fixed instant

std::string creds_text(const std::string &extra = "") {
  return std::string("access_key_id=") + kAccess +
         "\nsecret_access_key=" + kSecret + "\n" + extra;
}

bool parse_ok(const std::string &text) {
  [[maybe_unused]] const auto [ec, reason, credentials] =
      AwsCredentials::parse(text, kNow);
  return ec == std::errc{};
}

std::string parse_error(const std::string &text) {
  [[maybe_unused]] const auto [ec, reason, credentials] =
      AwsCredentials::parse(text, kNow);
  return ec == std::errc{} ? std::string{} : std::string(reason);
}

void test_credentials() {
  {
    [[maybe_unused]] const auto [ec, reason, credentials] =
        AwsCredentials::parse(creds_text(), kNow);
    CHECK(ec == std::errc{});
    CHECK(!credentials.has_session_token());
    const std::string json(credentials.to_credential_process_json());
    CHECK(json == std::string("{\"Version\":1,\"AccessKeyId\":\"") + kAccess +
                      "\",\"SecretAccessKey\":\"" + kSecret + "\"}\n");
  }
  {
    // Temporary credentials: token + future expiration, CRLF, comments,
    // ~/.aws/credentials spelling and mixed case.
    const std::string text = std::string("# comment\r\nAWS_ACCESS_KEY_ID = ") +
                             kAccess + "\r\naws_secret_access_key=" + kSecret +
                             "\r\nAWS_SESSION_TOKEN=" + kToken +
                             "\r\nExpiration=2030-01-01T00:00:00Z\r\n";
    [[maybe_unused]] const auto [ec, reason, credentials] =
        AwsCredentials::parse(text, kNow);
    CHECK(ec == std::errc{});
    CHECK(credentials.has_session_token());
    const std::string json(credentials.to_credential_process_json());
    CHECK(json == std::string("{\"Version\":1,\"AccessKeyId\":\"") + kAccess +
                      "\",\"SecretAccessKey\":\"" + kSecret +
                      "\",\"SessionToken\":\"" + kToken +
                      "\",\"Expiration\":\"2030-01-01T00:00:00Z\"}\n");
  }

  {
    [[maybe_unused]] const auto [ec, reason, credentials] =
        AwsCredentials::parse("", kNow);
    CHECK(ec == std::errc::invalid_argument);
    CHECK(ec != std::errc{});
    const SecureString json = credentials.to_credential_process_json();
    CHECK(json == "{\"Version\":1,\"AccessKeyId\":\"\","
                  "\"SecretAccessKey\":\"\"}\n");
  }

  CHECK(!parse_ok(""));
  CHECK(!parse_ok(std::string("access_key_id=") + kAccess + "\n"));
  CHECK(!parse_ok(std::string("secret_access_key=") + kSecret + "\n"));
  CHECK(parse_error(creds_text("extra=1\n")) ==
        "unknown key in credentials file");
  CHECK(parse_error(creds_text(std::string(kSecret) + "=1\n")) ==
        "unknown key in credentials file");
  CHECK(parse_error(creds_text(std::string("access_key_id=") + kAccess + "\n"))
            .find("duplicate") != std::string::npos);
  CHECK(!parse_ok(creds_text("not a pair\n")));

  // Anything that could escape the JSON string, or is not an AWS charset.
  CHECK(!parse_ok(std::string("access_key_id=") + kAccess +
                  "\"}\nsecret_access_key=" + kSecret + "\n"));
  CHECK(!parse_ok(std::string("access_key_id=akiaiosfodnn7example\n"
                              "secret_access_key=") +
                  kSecret + "\n"));
  CHECK(!parse_ok(std::string("access_key_id=") + kAccess +
                  "\nsecret_access_key=short\n"));
  CHECK(!parse_ok(std::string("access_key_id=") + kAccess +
                  "\nsecret_access_key=" + "a\\b" + std::string(30, 'a') +
                  "\n"));
  CHECK(!parse_ok(std::string("access_key_id=") + kAccess +
                  "\nsecret_access_key=" + kSecret +
                  "\nsession_token=has space in it xxxxxxxx\n"
                  "expiration=2030-01-01T00:00:00Z\n"));

  // Expiration handling.
  CHECK(!parse_ok(creds_text("expiration=2001-01-01T00:00:00Z\n")));
  CHECK(parse_error(creds_text("expiration=2001-01-01T00:00:00Z\n"))
            .find("expired") != std::string::npos);
  CHECK(!parse_ok(creds_text("expiration=tomorrow\n")));
  CHECK(!parse_ok(creds_text("expiration=2030-01-01 00:00:00\n")));
  CHECK(parse_ok(creds_text("expiration=2030-01-01T00:00:00Z\n")));
  CHECK(parse_ok(creds_text("expiration=2032-02-29T00:00:00Z\n")));
  for (const char *invalid :
       {"2030-02-29T00:00:00Z", "2030-04-31T00:00:00Z", "2030-01-01T00:00:60Z",
        "2030-1-01T00:00:000Z", "2030-01-01T00:00:00ZZ",
        "2030- 1-01T00:00:00Z"}) {
    CHECK(!parse_ok(creds_text(std::string("expiration=") + invalid + "\n")));
  }
  std::string nul_expiry = "expiration=2030-01-01T00:00:00Z";
  nul_expiry[18] = '\0';
  CHECK(!parse_ok(creds_text(nul_expiry)));
  // A token without an expiry would be cached by the CLI forever.
  CHECK(!parse_ok(creds_text(std::string("session_token=") + kToken + "\n")));

  // Errors must never echo secret values.
  const std::string err =
      parse_error(creds_text(std::string("session_token=bad token\n")));
  CHECK(err.find(kSecret) == std::string::npos);
  CHECK(err.find(kAccess) == std::string::npos);
}

void test_environment() {
  using V = AwsCliVerifier;
  const std::string clean = std::string("HOME=/home/u") + '\0' +
                            "PATH=/usr/bin" + '\0' + "AWS_PROFILE=prod" + '\0';
  CHECK(!V::forbidden_environment(clean).has_value());
  CHECK(!V::forbidden_environment("").has_value());

  for (const char *bad : {"LD_PRELOAD=/tmp/x.so",
                          "LD_LIBRARY_PATH=/tmp",
                          "LD_AUDIT=/tmp/a.so",
                          "PYTHONPATH=/tmp",
                          "PYTHONSTARTUP=/tmp/s.py",
                          "MALLOC_PERTURB_=1",
                          "AWS_ENDPOINT_URL=https://evil",
                          "AWS_ENDPOINT_URL_S3=https://evil",
                          "AWS_CA_BUNDLE=/tmp/ca.pem",
                          "SSL_CERT_FILE=/tmp/ca.pem",
                          "REQUESTS_CA_BUNDLE=/tmp/ca.pem",
                          "AWS_CONFIG_FILE=/tmp/cfg",
                          "GCONV_PATH=/tmp",
                          "AWS_CLI_AUTO_PROMPT=on",
                          "AWS_CLI_AUTO_PROMPT=ON-PARTIAL",
                          "OPENSSL_CONF=/tmp/o.cnf",
                          "OPENSSL_MODULES=/tmp/m",
                          "OPENSSL_ENGINES=/tmp/e",
                          "AWS_ACCESS_KEY_ID=AKIAEXAMPLE",
                          "AWS_STS_REGIONAL_ENDPOINTS=legacy",
                          "AWS_EC2_METADATA_SERVICE_ENDPOINT=http://evil",
                          "AWS_ROLE_ARN=arn:aws:iam::1:role/x",
                          "AWS_USE_FIPS_ENDPOINT=true"}) {
    const std::string env = clean + bad + '\0';
    const auto hit = V::forbidden_environment(env);
    CHECK(hit.has_value());
    if (hit) {
      CHECK(std::string(bad).starts_with(*hit));
    }
  }

  const std::string bundle = "/usr/local/aws-cli/v2/2.0/dist";
  const std::string bundled = clean + "LD_LIBRARY_PATH=" + bundle + '\0';
  CHECK(!V::forbidden_environment(bundled, bundle));
  CHECK(V::forbidden_environment(bundled));
  CHECK(V::forbidden_environment(bundled + "LD_LIBRARY_PATH_ORIG=" + bundle,
                                 bundle) == "LD_LIBRARY_PATH_ORIG");
  CHECK(V::forbidden_environment(bundled + "LD_LIBRARY_PATH=" + bundle,
                                 bundle) == "LD_LIBRARY_PATH");
  CHECK(V::forbidden_environment(clean + "LD_LIBRARY_PATH=" + bundle + ":/tmp",
                                 bundle) == "LD_LIBRARY_PATH");
  CHECK(V::forbidden_environment(bundled + "LD_AUDIT=/tmp/x.so", bundle) ==
        "LD_AUDIT");
  CHECK(V::forbidden_environment(clean + "AWS_DATA_PATH=/tmp/models" + '\0') ==
        "AWS_DATA_PATH");
  CHECK(V::forbidden_environment(bundled + "AWS_DATA_PATH=/tmp/models" + '\0',
                                 bundle) == "AWS_DATA_PATH");

  CHECK(!V::forbidden_environment(clean + "AWS_CLI_AUTO_PROMPT=off"));
  // The AWS_* namespace is deny-by-default; only inert settings pass.
  for (const char *fine :
       {"AWS_REGION=eu-west-1", "AWS_DEFAULT_REGION=us-east-1",
        "AWS_PAGER=", "AWS_DEFAULT_OUTPUT=json", "AWS_MAX_ATTEMPTS=3",
        "AWS_RETRY_MODE=standard", "AWS_DEFAULT_PROFILE=dev"}) {
    CHECK(!V::forbidden_environment(clean + fine + '\0').has_value());
  }

  // Names must match; look-alikes and values must not.
  CHECK(!V::forbidden_environment(std::string("MY_LD_PRELOAD=1") + '\0')
             .has_value());
  CHECK(!V::forbidden_environment(std::string("NOTE=LD_PRELOAD=x") + '\0')
             .has_value());
  CHECK(!V::forbidden_environment(std::string("AWS_PROFILE=LD_PRELOAD") + '\0')
             .has_value());
}

void test_cli_config() {
  using V = AwsCliVerifier;
  std::istringstream clean(
      "\n \t# [plugins]\n ; [plugins]\n[profile prod]\n"
      "description = mentions [plugins]\nCLI_AUTO_PROMPT : OFF \n"
      "[plugins] other]\n");
  CHECK(V::scan_cli_config(clean, true).passed());

  for (const char *config :
       {"[plugins]", " \t[plugins] \r\n", "[plugins] # comment\n",
        "[profile prod]\r[plugins]\r", "\u00a0[plugins]\n"}) {
    std::istringstream blocked(config);
    CHECK(V::scan_cli_config(blocked, true).result ==
          std::errc::permission_denied);
  }

  for (const char *config : {"[default]\ncli_auto_prompt=on\n",
                             "[DEFAULT]\rCLI_AUTO_PROMPT\u00a0: On-Partial\r",
                             "[profile prod]\ncli_auto_prompt =\n  on\n"}) {
    for (bool check_plugins : {true, false}) {
      std::istringstream blocked(config);
      CHECK(V::scan_cli_config(blocked, check_plugins).result ==
            std::errc::permission_denied);
    }
  }
  std::istringstream credentials("[plugins]\ncli_auto_prompt = off\n");
  CHECK(V::scan_cli_config(credentials, false).passed());

  std::istringstream unreadable;
  unreadable.setstate(std::ios::badbit);
  CHECK(V::scan_cli_config(unreadable, true).result == std::errc::io_error);
}

void test_arguments() {
  using V = AwsCliVerifier;
  CHECK(!V::forbidden_arguments({"aws", "s3", "ls", "--profile", "prod"})
             .has_value());
  CHECK(!V::forbidden_arguments({}).has_value());
  CHECK(!V::forbidden_arguments({"aws", "sts", "get-caller-identity",
                                 "--output", "json", "--region", "eu-west-1"})
             .has_value());

  for (const char *bad :
       {"--debug", "--no-verify-ssl", "--endpoint-url",
        "--endpoint-url=http://x", "--ca-bundle", "--ca-bundle=/tmp/ca",
        "--endpoint", "--no-verify", "--deb", "export-credentials",
        "--cli-auto-prompt", "--cli-auto-p"}) {
    const auto hit = V::forbidden_arguments({"aws", "configure", bad});
    CHECK(hit.has_value());
    if (hit) {
      CHECK(*hit == bad);
    }
  }
  // Positional text after "--" is data.
  CHECK(!V::forbidden_arguments({"aws", "s3", "cp", "--", "--debug"})
             .has_value());
  CHECK(!V::forbidden_arguments(
      {"aws", "--", "s3", "cp", "--", "export-credentials"}));
  CHECK(!V::forbidden_arguments({"aws", "s3", "ls", "--no-cli-auto-prompt"}));
  CHECK(V::forbidden_arguments({"aws", "s3", "cp", "--",
                                "--cli-auto-prompt"}) == "--cli-auto-prompt");
  CHECK(V::forbidden_arguments({"aws", "--", "configure",
                                "export-credentials"}) == "export-credentials");
  CHECK(V::forbidden_arguments({"aws", "--profile", "prod", "--", "configure",
                                "export-credentials"}) == "export-credentials");
  CHECK(V::forbidden_arguments({"aws", "configure", "--",
                                "export-credentials"}) == "export-credentials");
  // argv[0] is the program, not an option.
  CHECK(!V::forbidden_arguments({"--debug"}).has_value());
  // Longer options that merely share a prefix with a forbidden one.
  CHECK(!V::forbidden_arguments({"aws", "x", "--dry-run"}).has_value());
  CHECK(!V::forbidden_arguments({"aws", "x", "--debugger-name"}).has_value());
}

void test_maps() {
  const std::string maps =
      "55d0c2a00000-55d0c2a21000 r--p 00000000 08:01 1310725   "
      "/usr/local/aws-cli/v2/2.0/dist/aws\n"
      "7f0000000000-7f0000100000 r-xp 00000000 08:01 42        "
      "/usr/lib/libc.so.6\n"
      "7f0000200000-7f0000201000 r-xp 00000000 08:01 43        "
      "/tmp/evil dir/lib.so\n"
      "7f0000300000-7f0000301000 r-xp 00000000 00:00 0 \n"
      "7ffd10000000-7ffd10002000 r-xp 00000000 00:00 0          [vdso]\n"
      "7f0000400000-7f0000401000 r-xs 00000000 00:01 44        "
      "/memfd:libffi (deleted)\n"
      "7f0000500000-7f0000501000 rw-p 00000000 08:01 45        "
      "/home/user/data.so\n"
      "7f0000600000-7f0000601000 r-xp 00000000 08:01 46        "
      "/opt/old.so (deleted)\n"
      "7f0000700000-7f0000701000 r-xp 00000000 08:01 42        "
      "/usr/lib/libc.so.6\n";
  const auto paths = AwsCliVerifier::executable_mapping_paths(maps);
  const std::vector<std::string> expected = {
      "/memfd:libffi (deleted)", "/opt/old.so (deleted)",
      "/tmp/evil dir/lib.so", "/usr/lib/libc.so.6"};
  CHECK(paths == expected);
  CHECK(AwsCliVerifier::executable_mapping_paths("").empty());
  CHECK(AwsCliVerifier::executable_mapping_paths("garbage\n\n").empty());
}

void test_trusted_file() {
  // Root-owned system files qualify even when not executable...
  CHECK(Security::trusted_file("/etc/passwd").has_value());
  CHECK(!Security::trusted_executable("/etc/passwd").has_value());
  CHECK(Security::trusted_directory("/etc").has_value());
  CHECK(!Security::trusted_directory("/etc/passwd").has_value());
  // ...a file under a world-writable directory never does, nor does a
  // relative path or a missing file.
  char dir[] = "/tmp/methuselah-trust-XXXXXX";
  CHECK(::mkdtemp(dir) != nullptr);
  const std::string lib = std::string(dir) + "/lib.so";
  std::ofstream(lib) << "x";
  CHECK(!Security::trusted_file(lib).has_value());
  CHECK(!Security::trusted_directory(dir).has_value());
  CHECK(!Security::trusted_file("etc/passwd").has_value());
  CHECK(!Security::trusted_file("/etc/does-not-exist").has_value());
  ::unlink(lib.c_str());
  ::rmdir(dir);
}

void test_trust_policy() {
  namespace fs = std::filesystem;
  if (::geteuid() == 0) {
    std::printf("SKIP trust policy: running as root\n");
    return;
  }

  const fs::path base = fs::current_path() / "methuselah-trust-policy";
  std::error_code ec;
  fs::remove_all(base, ec);
  fs::create_directories(base, ec);
  if (ec) {
    std::printf("SKIP trust policy: cannot create test directory\n");
    return;
  }
  fs::permissions(base, fs::perms::owner_all, fs::perm_options::replace, ec);
  const fs::path file = base / "sh";
  std::ofstream(file) << "x";
  ::chmod(file.c_str(), 0755);

  TrustPolicy policy;
  policy.owners = {0, ::geteuid()};
  const auto dir = Security::trusted_directory(base, policy);
  const auto exe = Security::trusted_executable(file, policy);
  const auto regular = Security::trusted_file(file, policy);
  if (!dir || !exe || !regular) {
    std::printf("SKIP trust policy: test path has untrusted ancestors\n");
  } else {
    CHECK(*dir == base);
    CHECK(*exe == file);
    CHECK(*regular == file);
    // Adding the owner must not change the default root-only policy.
    CHECK(!Security::trusted_directory(base).has_value());
    CHECK(!Security::trusted_executable(file).has_value());
    CHECK(!Security::trusted_file(file).has_value());
  }
  fs::remove_all(base, ec);
}

void test_aws_defaults() {
  const auto options = AwsCliVerifier::default_options();
  const auto service =
      std::filesystem::path("/opt/methuselah/aws-cli/v2/current/dist/aws");
  CHECK(std::find(options.candidates.begin(), options.candidates.end(),
                  service) != options.candidates.end());
  CHECK(std::find(options.install_owners.begin(), options.install_owners.end(),
                  0) != options.install_owners.end());
  CHECK(options.pin_file == "/etc/methuselah/aws-cli.sha256");
  if (::geteuid() != 0) {
    // The caller must never be allowed to own the CLI it is verified against.
    CHECK(std::find(options.install_owners.begin(),
                    options.install_owners.end(),
                    ::geteuid()) == options.install_owners.end());
  }
}

void test_pin_file_and_hash() {
  using V = AwsCliVerifier;
  const std::string d1(64, 'a');
  const std::string d2 =
      "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";

  auto pins = V::parse_pin_file("# aws 2.x\n\n" + d1 +
                                "  /usr/local/aws/aws\n" + d2 + "\n");
  CHECK(pins.has_value());
  if (pins) {
    CHECK(pins->size() == 2);
    CHECK((*pins)[0] == d1);
    CHECK((*pins)[1] ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  }
  CHECK(!V::parse_pin_file("").has_value());
  CHECK(!V::parse_pin_file("# only a comment\n").has_value());
  CHECK(!V::parse_pin_file(d1 + "\nnot-a-digest  file\n").has_value());
  CHECK(!V::parse_pin_file(std::string(63, 'a') + "\n").has_value());
  CHECK(!V::parse_pin_file(std::string(64, 'g') + "\n").has_value());

  int fds[2];
  CHECK(::pipe(fds) == 0);
  CHECK(::write(fds[1], "abc", 3) == 3);
  ::close(fds[1]);
  const auto digest = V::sha256_hex(fds[0]);
  ::close(fds[0]);
  CHECK(digest.has_value());
  if (digest) {
    CHECK(*digest ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  }
}

// --- verify() against real processes ------------------------------------

struct Child {
  pid_t pid = -1;
  ~Child() {
    if (pid > 0) {
      ::kill(-pid, SIGKILL); // the shell and its `sleep`
      ::waitpid(pid, nullptr, 0);
    }
  }
};

Child spawn(const std::string &program, std::vector<std::string> args,
            std::vector<std::string> env) {
  Child child;
  child.pid = ::fork();
  if (child.pid == 0) {
    // Own process group, and no inherited pipes: a lingering grandchild must
    // not keep the test runner's output pipe open.
    ::setpgid(0, 0);
    const int null = ::open("/dev/null", O_RDWR);
    if (null >= 0) {
      ::dup2(null, STDIN_FILENO);
      ::dup2(null, STDOUT_FILENO);
      ::dup2(null, STDERR_FILENO);
    }
    std::vector<char *> argv;
    for (auto &a : args) {
      argv.push_back(a.data());
    }
    argv.push_back(nullptr);
    std::vector<char *> envp;
    for (auto &e : env) {
      envp.push_back(e.data());
    }
    envp.push_back(nullptr);
    ::execve(program.c_str(), argv.data(), envp.data());
    ::_exit(127);
  }
  return child;
}

// Wait until the child has exec'd `program`, so /proc/<pid>/exe is final.
bool wait_for_exec(pid_t pid, const std::string &program) {
  struct stat want{};
  if (::stat(program.c_str(), &want) != 0) {
    return false;
  }
  const std::string link = "/proc/" + std::to_string(pid) + "/exe";
  for (int i = 0; i < 200; ++i) {
    struct stat got{};
    if (::stat(link.c_str(), &got) == 0 && got.st_dev == want.st_dev &&
        got.st_ino == want.st_ino) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return false;
}

// The verifier must use its configured owner policy, not just the Security
// helper, when the CLI is owned by the service account instead of root.
void test_service_install() {
  namespace fs = std::filesystem;
  const auto shell = Security::trusted_executable("/bin/sh");
  if (::geteuid() == 0 || !shell) {
    std::printf("SKIP service install: needs a non-root caller and /bin/sh\n");
    return;
  }

  const fs::path base = fs::current_path() / "methuselah-service-install";
  std::error_code ec;
  fs::remove_all(base, ec);
  fs::create_directories(base, ec);
  if (ec) {
    std::printf("SKIP service install: cannot create test directory\n");
    return;
  }
  fs::permissions(base, fs::perms::owner_all, fs::perm_options::replace, ec);
  const fs::path copy = base / "sh";
  fs::copy_file(*shell, copy, ec);
  if (ec) {
    std::printf("SKIP service install: cannot copy /bin/sh\n");
    fs::remove_all(base, ec);
    return;
  }
  ::chmod(copy.c_str(), 0755);

  TrustPolicy policy;
  policy.owners = {0, ::geteuid()};
  if (!Security::trusted_executable(copy, policy)) {
    std::printf("SKIP service install: test path has untrusted ancestors\n");
    fs::remove_all(base, ec);
    return;
  }

  AwsCliVerifier::Options options;
  options.min_ptrace_scope = 0;
  options.candidates = {copy};
  options.required_name = "sh";
  options.install_owners = policy.owners;
  options.pin_file = base / "missing-pin";
  const AwsCliVerifier verifier(options);
  {
    Child child = spawn(copy.string(), {"sh", "-c", "sleep 10; true"},
                        {"HOME=/", "AWS_PROFILE=p"});
    CHECK(wait_for_exec(child.pid, copy.string()));
    const auto [result, reason] = verifier.verify(child.pid);
    if (result != std::errc{}) {
      std::fprintf(stderr, "  unexpected verdict: %.*s\n",
                   static_cast<int>(reason.size()), reason.data());
    }
    CHECK(result == std::errc{});
  }
  fs::remove_all(base, ec);
}

// Every verify_*() call returns the same SecurityVerdict shape.
void test_verdict() {
  // Only string literals can become a reason, so it can never dangle.
  static_assert(
      std::is_constructible_v<SecurityVerdict, std::errc, const char (&)[3]>);
  static_assert(
      !std::is_constructible_v<SecurityVerdict, std::errc, std::string>);
  static_assert(
      !std::is_constructible_v<SecurityVerdict, std::errc, const char *>);
  static_assert(
      !std::is_constructible_v<SecurityVerdict, std::errc, std::string_view>);

  constexpr SecurityVerdict none;
  static_assert(none.result == std::errc::io_error && none.reason.empty());
  CHECK(!none.passed());

  constexpr SecurityVerdict yes{std::errc{}, "ok"};
  const auto [result, reason] = yes; // structured binding
  CHECK(result == std::errc{});
  CHECK(reason == "ok");
  CHECK(yes.passed());
  constexpr SecurityVerdict no{std::errc::permission_denied, "no"};
  CHECK(!no.passed());

  // The test runner is none of git, gpg, ssh or aws: each verifier must refuse
  // it and say why.
  const Security security;
  const SecurityVerdict verdicts[] = {
      security.verify_git(), security.verify_gpg(), security.verify_ssh(),
      security.verify_aws(::getpid())};
  const auto invalid_aws_caller = security.verify_aws(0);
  CHECK(invalid_aws_caller.result == std::errc::io_error);
  CHECK(invalid_aws_caller.reason == "no AWS CLI parent process");
  for (const auto &verdict : verdicts) {
    CHECK(!verdict.passed());
    CHECK(!verdict.reason.empty());
  }
}

std::string iso_utc(std::time_t when) {
  struct tm parts{};
  ::gmtime_r(&when, &parts);
  char out[32];
  std::strftime(out, sizeof(out), "%Y-%m-%dT%H:%M:%SZ", &parts);
  return out;
}

void test_expiry_window() {
  const std::string token = std::string("session_token=") + kToken + "\n";
  const auto text = [&](std::time_t offset) {
    return creds_text(token + "expiration=" + iso_utc(kNow + offset) + "\n");
  };
  CHECK(parse_ok(text(60 * 60)));
  CHECK(parse_ok(text(15 * 60 + 1)));
  // Inside botocore's refresh window the CLI would re-run the helper (and the
  // passphrase prompt) on every call.
  CHECK(!parse_ok(text(15 * 60)));
  CHECK(!parse_ok(text(15 * 60 - 1)));
  CHECK(!parse_ok(text(60)));
  CHECK(parse_error(text(60)).find("15 minutes") != std::string::npos);
  CHECK(parse_error(text(-60)).find("expired") != std::string::npos);
}

void test_unsafe_mappings() {
  using V = AwsCliVerifier;
  const std::string file_exec =
      "55d0-55d1 r-xp 00000000 08:01 1234  /usr/local/aws-cli/v2/current/dist/"
      "aws\n";
  const std::string file_data =
      "55d1-55d2 rw-p 00001000 08:01 1234  /usr/local/aws-cli/v2/current/dist/"
      "aws\n";
  const std::string anon_data = "7f00-7f10 rw-p 00000000 00:00 0 \n";
  const std::string special =
      "7ffc-7ffd r-xp 00000000 00:00 0                  [vdso]\n"
      "ff60-ff61 --xp 00000000 00:00 0                  [vsyscall]\n"
      "7f20-7f21 r-xs 00000000 00:01 77  /memfd:libffi (deleted)\n";
  CHECK(V::unsafe_mapping("") == V::UnsafeMapping::none);
  CHECK(V::unsafe_mapping("garbage\n\n") == V::UnsafeMapping::none);
  CHECK(V::unsafe_mapping(file_exec + file_data + anon_data + special) ==
        V::UnsafeMapping::none);
  CHECK(V::unsafe_mapping(file_exec + "7f30-7f31 rwxp 00000000 00:00 0 \n") ==
        V::UnsafeMapping::anonymous_writable_executable);
  CHECK(V::unsafe_mapping("7f30-7f31 rwxp 00000000 08:01 9  /usr/lib/x.so\n") ==
        V::UnsafeMapping::file_writable_executable);
  CHECK(V::unsafe_mapping("7f10-7f11 r-xp 00000000 00:00 0 \n"
                          "7f20-7f21 rwxs 00000000 00:01 77  "
                          "/memfd:libffi (deleted)\n") ==
        V::UnsafeMapping::file_writable_executable);
  CHECK(V::unsafe_mapping(file_exec + "7f40-7f41 r-xp 00000000 00:00 0 \n") ==
        V::UnsafeMapping::anonymous_executable);
  CHECK(V::unsafe_mapping("7f40-7f41 r-xp 00000000 00:00 0   [anon:evil]\n") ==
        V::UnsafeMapping::anonymous_executable);
  CHECK(V::unsafe_mapping("7f40-7f41 r-xp 00000000 00:01 5  /memfd:evil "
                          "(deleted)\n") == V::UnsafeMapping::none);
}

void test_ptrace_scope_parse() {
  using V = AwsCliVerifier;
  CHECK(V::parse_ptrace_scope("0\n") == 0);
  CHECK(V::parse_ptrace_scope("1") == 1);
  CHECK(V::parse_ptrace_scope("2\n") == 2);
  CHECK(V::parse_ptrace_scope("3\n") == 3);
  for (const char *bad : {"", "\n", "4", "-1", "two", "2x", "2 2", "02x"}) {
    CHECK(!V::parse_ptrace_scope(bad).has_value());
  }
}

class PolicyFixture {
public:
  PolicyFixture() {
    if (const char *dir = ::mkdtemp(directory_)) {
      file = std::filesystem::path(dir) / "policy";
    }
  }
  ~PolicyFixture() {
    if (!file.empty()) {
      ::unlink(file.c_str());
      ::rmdir(directory_);
    }
  }

  bool write(std::string_view text) const {
    std::ofstream out(file);
    out << text;
    out.close();
    CHECK(out.good());
    return out.good();
  }

  std::filesystem::path file;

private:
  char directory_[sizeof("/tmp/methuselah-policy-XXXXXX")] =
      "/tmp/methuselah-policy-XXXXXX";
};

void test_signer_policy() {
  using S = AwsSigners;
  const std::string fpr40(40, 'a');
  const std::string fpr64(64, 'B');
  const auto entries = S::parse("# who signs what\n\nprod " + fpr40 +
                                "\n  dev\t" + fpr64 + "  \n");
  CHECK(entries.has_value());
  if (entries) {
    CHECK(entries->size() == 2);
    const auto prod = S::find(*entries, "prod");
    CHECK(prod.passed() && prod.required());
    CHECK(prod.fingerprint == std::string(40, 'A')); // normalised
    CHECK(S::find(*entries, "dev").fingerprint == fpr64);
    // An unlisted profile is simply not enforced.
    const auto other = S::find(*entries, "stage");
    CHECK(other.passed() && !other.required());
  }
  CHECK(S::parse("").has_value() && S::parse("")->empty());
  CHECK(!S::parse("prod\n"));                            // no fingerprint
  CHECK(!S::parse("prod " + std::string(39, 'a')));      // wrong length
  CHECK(!S::parse("prod " + std::string(40, 'g')));      // not hex
  CHECK(!S::parse("prod " + fpr40 + " extra"));          // trailing junk
  CHECK(!S::parse("prod " + fpr40 + "\nprod " + fpr40)); // duplicate

  // An absent policy file enforces nothing; one that cannot be trusted fails
  // closed rather than silently dropping the requirement.
  const auto none = S::load("/nonexistent/methuselah/aws-signers", "prod");
  CHECK(none.passed() && !none.required());
  CHECK(!S::parse("../prod " + fpr40));
  CHECK(!S::parse(std::string("prod\0suffix", 11) + " " + fpr40));
  CHECK(!S::parse(std::string(65, 'a') + " " + fpr40));
  CHECK(S::parse("prod_1-dev.example@team " + fpr40).has_value());

  const PolicyFixture fixture;
  CHECK(!fixture.file.empty());
  if (fixture.file.empty() || !fixture.write("prod " + fpr40 + "\n")) {
    return;
  }
  const auto untrusted = S::load(fixture.file, "prod");
  CHECK(untrusted.result == std::errc::io_error && !untrusted.required());
}

void test_output_channel() {
  using V = AwsCliVerifier;
  int fds[2];
  const int pipe_result = ::pipe2(fds, O_CLOEXEC);
  CHECK(pipe_result == 0);
  if (pipe_result != 0) {
    return;
  }
  // This process holds both ends, so it counts as the reader.
  CHECK(V::verify_output_channel(::getpid(), fds[1]).passed());

  const pid_t reader = ::fork();
  if (reader == 0) {
    ::close(fds[1]);
    for (;;) {
      ::pause();
    }
  }
  CHECK(reader > 0);
  if (reader > 0) {
    const auto verdict = V::verify_output_channel(::getpid(), fds[1]);
    CHECK(verdict.reason == "another process holds a read end of stdout");
    ::kill(reader, SIGKILL);
    ::waitpid(reader, nullptr, 0);
    CHECK(V::verify_output_channel(::getpid(), fds[1]).passed());
  }

  // Not a pipe at all.
  const int null = ::open("/dev/null", O_WRONLY | O_CLOEXEC);
  CHECK(V::verify_output_channel(::getpid(), null).result ==
        std::errc::permission_denied);
  ::close(null);

  // A child that does not hold the pipe cannot be the reader.
  if (const auto shell = Security::trusted_executable("/bin/sh")) {
    Child other =
        spawn(shell->string(), {"sh", "-c", "sleep 10; true"}, {"HOME=/"});
    CHECK(wait_for_exec(other.pid, shell->string()));
    CHECK(V::verify_output_channel(other.pid, fds[1]).result ==
          std::errc::permission_denied);
  }

  // Holding only the write end is not reading it.
  ::close(fds[0]);
  CHECK(V::verify_output_channel(::getpid(), fds[1]).result ==
        std::errc::permission_denied);
  ::close(fds[1]);
}

// A real process whose libffi closures live in anonymous rwx memory: strict by
// default, accepted only with a root-owned waiver.
void test_anonymous_exec_waiver() {
  const auto python = Security::trusted_executable("/usr/bin/python3");
  if (!python) {
    std::printf("SKIP anonymous exec: no root-owned /usr/bin/python3\n");
    return;
  }
  AwsCliVerifier::Options options;
  options.min_ptrace_scope = 0;
  options.candidates = {"/usr/bin/python3"};
  options.required_name = python->filename().string();
  options.pin_file = "/nonexistent/methuselah/pin";

  Child child = spawn(python->string(),
                      {"python3", "-c",
                       "import ctypes, time\n"
                       "cb = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)"
                       "(lambda x: x)\n"
                       "time.sleep(10)"},
                      {"HOME=/"});
  CHECK(wait_for_exec(child.pid, python->string()));
  bool anonymous = false;
  for (int i = 0; i < 60 && !anonymous; ++i) {
    const auto maps = ProcessInfo::readProc(child.pid, "maps", 16U << 20);
    anonymous =
        maps &&
        AwsCliVerifier::unsafe_mapping(*maps) ==
            AwsCliVerifier::UnsafeMapping::anonymous_writable_executable;
    if (!anonymous) {
      ::usleep(50'000);
    }
  }
  if (!anonymous) {
    std::printf("SKIP anonymous exec: libffi here uses no anonymous rwx\n");
    return;
  }
  const auto strict = AwsCliVerifier(options).verify(child.pid);
  CHECK(strict.result == std::errc::permission_denied);
  CHECK(std::string(strict.reason).find("executable memory") !=
        std::string::npos);
  if (Security::trusted_file("/etc/passwd")) {
    options.anonymous_exec_waiver_file = "/etc/passwd"; // stands in for it
    const auto waived = AwsCliVerifier(options).verify(child.pid);
    if (!waived.passed()) {
      std::fprintf(stderr, "  unexpected verdict: %.*s\n",
                   static_cast<int>(waived.reason.size()),
                   waived.reason.data());
    }
    CHECK(waived.passed());
  }
  options.anonymous_exec_waiver_file = "/tmp"; // not a root-owned file
  CHECK(AwsCliVerifier(options).verify(child.pid).result ==
        std::errc::permission_denied);
}

// Reserve two pages and replace the second with a file mapping, so the
// anonymous executable entry precedes the writable executable file entry.
void test_file_mapping_with_waiver() {
  const auto python = Security::trusted_executable("/usr/bin/python3");
  if (!python || !Security::trusted_file("/etc/passwd")) {
    std::printf(
        "SKIP mixed executable maps: need trusted python3 and /etc/passwd\n");
    return;
  }
  AwsCliVerifier::Options options;
  options.min_ptrace_scope = 0;
  options.candidates = {"/usr/bin/python3"};
  options.required_name = python->filename().string();
  options.pin_file = "/nonexistent/methuselah/pin";
  options.anonymous_exec_waiver_file = "/etc/passwd";

  Child child = spawn(python->string(), {"python3", "-c", R"PY(
import ctypes, mmap, os, time
map_pages = ctypes.CDLL(None).mmap
map_pages.restype = ctypes.c_void_p
map_pages.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                      ctypes.c_int, ctypes.c_int, ctypes.c_long)
page = mmap.PAGESIZE
rwx = mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC
base = map_pages(None, 2 * page, rwx, mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, -1, 0)
assert base != ctypes.c_void_p(-1).value
map_fixed = 0x10  # Linux MAP_FIXED
fd = os.open('/etc/passwd', os.O_RDONLY)
assert map_pages(base + page, page, rwx, mmap.MAP_PRIVATE | map_fixed, fd, 0) == base + page
time.sleep(10)
)PY"},
                      {"HOME=/"});
  CHECK(wait_for_exec(child.pid, python->string()));
  for (int i = 0; i < 60; ++i) {
    const auto maps = ProcessInfo::readProc(child.pid, "maps", 16U << 20);
    if (maps && maps->find("/etc/passwd") != std::string::npos) {
      const auto verdict = AwsCliVerifier(options).verify(child.pid);
      CHECK(verdict.result == std::errc::permission_denied);
      CHECK(verdict.reason == "AWS CLI has a writable executable file mapping");
      return;
    }
    ::usleep(50'000);
  }
  CHECK(false); // The mixed mapping fixture did not become ready.
}

void test_verify() {
  // Stand a system shell in for `aws`: same checks, real kernel state.
  const auto shell = Security::trusted_executable("/bin/sh");
  if (!shell) {
    std::printf("SKIP verify(): /bin/sh is not a root-owned executable here\n");
    return;
  }
  AwsCliVerifier::Options options;
  options.min_ptrace_scope = 0;
  options.candidates = {"/bin/sh"};
  options.required_name = shell->filename().string();
  const AwsCliVerifier verifier(options);
  const std::vector<std::string> sh_args = {"sh", "-c", "sleep 10; true"};
  const std::vector<std::string> clean_env = {"HOME=/", "AWS_PROFILE=p"};

  {
    Child ok = spawn(shell->string(), sh_args, clean_env);
    CHECK(wait_for_exec(ok.pid, shell->string()));
    const auto [result, reason] = verifier.verify(ok.pid);
    if (result != std::errc{}) {
      std::fprintf(stderr, "  unexpected verdict: %.*s\n",
                   static_cast<int>(reason.size()), reason.data());
    }
    CHECK(result == std::errc{});
    CHECK(reason == "ok");

    // A non-directory component yields ENOTDIR, not an absent pin.
    auto bad_pin = options;
    bad_pin.pin_file = "/dev/null/aws-cli.sha256";
    const auto pin_verdict = AwsCliVerifier(bad_pin).verify(ok.pid);
    CHECK(pin_verdict.result == std::errc::io_error);
    CHECK(pin_verdict.reason == "cannot inspect AWS CLI pin file");
  }
  {
    Child bad = spawn(shell->string(), sh_args, {"HOME=/tmp"});
    CHECK(wait_for_exec(bad.pid, shell->string()));
    const auto verdict = verifier.verify(bad.pid);
    CHECK(verdict.result == std::errc::permission_denied);
    CHECK(verdict.reason.find("root controlled") != std::string::npos);
  }
  {
    auto env = clean_env;
    env.push_back("LD_PRELOAD=/tmp/evil.so");
    Child bad = spawn(shell->string(), sh_args, env);
    CHECK(wait_for_exec(bad.pid, shell->string()));
    const auto verdict = verifier.verify(bad.pid);
    CHECK(verdict.result == std::errc::permission_denied);
    CHECK(verdict.reason == "AWS CLI environment variable not allowed");
  }
  {
    auto args = sh_args;
    args.push_back("--endpoint-url=http://evil");
    Child bad = spawn(shell->string(), args, clean_env);
    CHECK(wait_for_exec(bad.pid, shell->string()));
    const auto verdict = verifier.verify(bad.pid);
    CHECK(verdict.result == std::errc::permission_denied);
    CHECK(verdict.reason == "AWS CLI argument not allowed");
  }
  {
    // This test binary is not the configured CLI.
    CHECK(verifier.verify(::getpid()).result == std::errc::permission_denied);
  }
  {
    // A byte-identical copy in a user-writable directory is still not the
    // installed CLI: identity is the inode, not the contents or the name.
    char dir[] = "/tmp/methuselah-test-XXXXXX";
    CHECK(::mkdtemp(dir) != nullptr);
    const std::string copy = std::string(dir) + "/" + options.required_name;
    std::filesystem::copy_file(*shell, copy);
    ::chmod(copy.c_str(), 0755);

    Child fake = spawn(copy, sh_args, clean_env);
    CHECK(wait_for_exec(fake.pid, copy));
    CHECK(verifier.verify(fake.pid).result == std::errc::permission_denied);

    // Replaced on disk after start.
    ::unlink(copy.c_str());
    const auto deleted = verifier.verify(fake.pid);
    CHECK(deleted.result == std::errc::permission_denied);
    ::rmdir(dir);
  }
  {
    // Yama must stop a same-user parent from attaching to the AWS CLI.
    const PolicyFixture fixture;
    CHECK(!fixture.file.empty());
    if (fixture.file.empty()) {
      return;
    }
    const auto &scope_file = fixture.file;
    AwsCliVerifier::Options strict = options;
    strict.min_ptrace_scope = 2;
    strict.ptrace_scope_file = scope_file;
    Child ok = spawn(shell->string(), sh_args, clean_env);
    CHECK(wait_for_exec(ok.pid, shell->string()));

    if (!fixture.write("1\n")) {
      return;
    }
    CHECK(AwsCliVerifier(strict).verify(ok.pid).result ==
          std::errc::permission_denied);
    if (!fixture.write("0\n")) {
      return;
    }
    CHECK(AwsCliVerifier(strict).verify(ok.pid).result ==
          std::errc::permission_denied);
    if (!fixture.write("banana\n")) {
      return;
    }
    CHECK(AwsCliVerifier(strict).verify(ok.pid).result ==
          std::errc::permission_denied);
    if (!fixture.write("2\n")) {
      return;
    }
    CHECK(AwsCliVerifier(strict).verify(ok.pid).passed());
    if (!fixture.write("3\n")) {
      return;
    }
    CHECK(AwsCliVerifier(strict).verify(ok.pid).passed());

    // No Yama at all is refused too, unless a root-owned waiver exists.
    ::unlink(scope_file.c_str());
    CHECK(AwsCliVerifier(strict).verify(ok.pid).result ==
          std::errc::permission_denied);
    strict.ptrace_waiver_file = "/etc/methuselah-test-no-such-waiver";
    CHECK(AwsCliVerifier(strict).verify(ok.pid).result ==
          std::errc::permission_denied);
    if (Security::trusted_file("/etc/passwd")) {
      strict.ptrace_waiver_file = "/etc/passwd"; // stands in for the waiver
      CHECK(AwsCliVerifier(strict).verify(ok.pid).passed());
    }
    // A waiver the user could have written does not count.
    strict.ptrace_waiver_file = "/tmp";
    CHECK(AwsCliVerifier(strict).verify(ok.pid).result ==
          std::errc::permission_denied);
  }
  {
    // No usable installation at all must fault, not pass or silently fail.
    AwsCliVerifier::Options none;
    none.min_ptrace_scope = 0;
    none.candidates = {"/nonexistent/aws"};
    Child ok = spawn(shell->string(), sh_args, clean_env);
    CHECK(wait_for_exec(ok.pid, shell->string()));
    CHECK(AwsCliVerifier(none).verify(ok.pid).result == std::errc::io_error);
  }
  {
    CHECK(verifier.verify(0).result == std::errc::io_error);
    CHECK(verifier.verify(1).result == std::errc::io_error);
  }
}

} // namespace

void test_text_util() {
  using namespace methuselah::strutil;
  CHECK(trim("  a b \t\r\n") == "a b");
  CHECK(trim("   ").empty());
  CHECK(trim("").empty());
  CHECK(trim("x") == "x");

  // next_line visits every line, including a last one without a newline and
  // empty lines in between, and leaves the rest in place.
  std::string_view text = "one\n\ntwo\nthree";
  CHECK(next_line(text) == "one");
  CHECK(text == "\ntwo\nthree");
  CHECK(next_line(text).empty());
  CHECK(next_line(text) == "two");
  CHECK(next_line(text) == "three");
  CHECK(text.empty());
  std::string_view trailing = "a\n";
  CHECK(next_line(trailing) == "a");
  CHECK(trailing.empty());

  CHECK(is_hex("0123456789abcdefABCDEF"));
  CHECK(is_hex(""));
  CHECK(!is_hex("12g4"));
  CHECK(!is_hex("12 4"));

  CHECK(ascii_upper("aBc-1z") == "ABC-1Z");
  CHECK(ascii_lower("aBc-1Z") == "abc-1z");
  // Bytes outside ASCII are never altered, whatever the locale says.
  CHECK(ascii_upper("\xe9") == "\xe9");
  CHECK(ascii_lower("\xc9") == "\xc9");
  CHECK(ascii_iequals("OfF", "off"));
  CHECK(ascii_iequals("off", "OFF"));
  CHECK(!ascii_iequals("of", "off"));
  CHECK(!ascii_iequals("offf", "off"));
  CHECK(ascii_iequals("", ""));
}

void test_fd_io() {
  // UniqueFd closes on destruction and on reset, and moves ownership.
  int raw = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
  CHECK(raw >= 0);
  {
    UniqueFd fd(raw);
    CHECK(fd.valid() && fd.get() == raw);
    UniqueFd moved(std::move(fd));
    CHECK(!fd.valid() && moved.get() == raw);
  }
  CHECK(::fcntl(raw, F_GETFD) == -1 && errno == EBADF);
  UniqueFd none;
  CHECK(!none.valid());
  CHECK(none.release() == -1);

  // read_all: an exact fit is accepted, one byte more is too large.
  char path[] = "/tmp/methuselah-fdio-XXXXXX";
  const int tmp = ::mkstemp(path);
  CHECK(tmp >= 0);
  const std::string payload(10000, 'x'); // spans several internal chunks
  CHECK(::write(tmp, payload.data(), payload.size()) ==
        static_cast<ssize_t>(payload.size()));

  const auto read_with_limit = [&](std::size_t limit) {
    CHECK(::lseek(tmp, 0, SEEK_SET) == 0);
    return read_all(tmp, limit);
  };
  const auto exact = read_with_limit(payload.size());
  CHECK(exact.status == ReadStatus::ok && exact.data == payload);
  const auto over = read_with_limit(payload.size() - 1);
  CHECK(over.status == ReadStatus::too_large);
  const auto roomy = read_with_limit(1U << 20);
  CHECK(roomy.status == ReadStatus::ok && roomy.data.size() == payload.size());

  // read_chunks streams without accumulating, so a sink can stop early.
  CHECK(::lseek(tmp, 0, SEEK_SET) == 0);
  std::size_t seen = 0;
  CHECK(read_chunks(tmp, [&](const char *, std::size_t n) {
          seen += n;
          return true;
        }) == ReadStatus::ok);
  CHECK(seen == payload.size());
  CHECK(::lseek(tmp, 0, SEEK_SET) == 0);
  CHECK(read_chunks(tmp, [](const char *, std::size_t) { return false; }) ==
        ReadStatus::too_large);

  ::close(tmp);
  ::unlink(path);
  CHECK(read_all(-1, 10).status == ReadStatus::io_error);
}

void test_read_trusted_file() {
  using Status = TrustedFileContent::Status;
  const auto status_of = [](const std::filesystem::path &file,
                            std::size_t max = 1024,
                            const TrustPolicy &policy = {}) {
    return Security::read_trusted_file(file, max, policy).status;
  };

  CHECK(status_of("/etc/does-not-exist-methuselah") == Status::absent);
  // ENOTDIR is "cannot inspect", not "absent": a missing policy file means no
  // policy, a broken path must not.
  CHECK(status_of("/dev/null/x") == Status::cannot_inspect);
  // Under a world-writable directory a file is never trusted.
  char dir[] = "/tmp/methuselah-trusted-read-XXXXXX";
  CHECK(::mkdtemp(dir) != nullptr);
  const std::string file = std::string(dir) + "/policy";
  std::ofstream(file) << "x";
  CHECK(status_of(file) == Status::untrusted);
  ::unlink(file.c_str());
  ::rmdir(dir);

  // A real root-owned file reads back verbatim.
  const auto passwd = Security::read_trusted_file("/etc/passwd", 1U << 20);
  CHECK(passwd.status == Status::ok && !passwd.data.empty());
  CHECK(status_of("/etc/passwd", 4) == Status::too_large);
  CHECK(status_of("/etc") == Status::untrusted); // not a regular file

  // The positive cases need a directory chain the policy trusts end to end.
  namespace fs = std::filesystem;
  const fs::path base = fs::current_path() / "methuselah-read-trusted";
  std::error_code ec;
  fs::remove_all(base, ec);
  fs::create_directories(base, ec);
  fs::permissions(base, fs::perms::owner_all, fs::perm_options::replace, ec);
  TrustPolicy policy;
  policy.owners = {0, ::geteuid()};
  if (ec || !Security::trusted_directory(base, policy)) {
    std::printf("SKIP read_trusted_file: test path has untrusted ancestors\n");
    fs::remove_all(base, ec);
    return;
  }
  const fs::path policy_file = base / "policy";
  const auto write = [&](const std::string &content, mode_t mode) {
    std::ofstream(policy_file, std::ios::trunc) << content;
    ::chmod(policy_file.c_str(), mode);
  };

  write("hello\n", 0644);
  const auto ok = Security::read_trusted_file(policy_file, 1024, policy);
  CHECK(ok.status == Status::ok && ok.data == "hello\n");
  write("", 0644);
  CHECK(Security::read_trusted_file(policy_file, 1024, policy).status ==
        Status::ok);
  write("12345678", 0644);
  CHECK(status_of(policy_file, 8, policy) == Status::ok); // exact fit
  CHECK(status_of(policy_file, 7, policy) == Status::too_large);
  write("x", 0664); // group-writable
  CHECK(status_of(policy_file, 1024, policy) == Status::untrusted);
  write("x", 0644);
  CHECK(status_of(policy_file, 1024) ==
        (::geteuid() == 0 ? Status::ok : Status::untrusted)); // default: root
  const fs::path link = base / "link";
  fs::create_symlink(policy_file, link, ec);
  CHECK(status_of(link, 1024, policy) == Status::ok); // vetted link target
  fs::remove_all(base, ec);
}

void test_decrypt_result() {
  DecryptResult fresh;
  CHECK(fresh.ok() && !fresh.not_signed());

  DecryptResult generic;
  generic.set_error("boom");
  CHECK(!generic.ok() && !generic.not_signed() && generic.error() == "boom");

  DecryptResult unsigned_result;
  unsigned_result.set_error(GpgDecryptor::kNotSignedError,
                            DecryptResult::Failure::not_signed);
  CHECK(!unsigned_result.ok() && unsigned_result.not_signed());

  // The reason survives moves; it must never be inferred from message text.
  DecryptResult moved(std::move(unsigned_result));
  CHECK(moved.not_signed() && moved.error() == GpgDecryptor::kNotSignedError);
  DecryptResult assigned;
  assigned = std::move(moved);
  CHECK(assigned.not_signed());
  DecryptResult same_text_other_reason;
  same_text_other_reason.set_error(GpgDecryptor::kNotSignedError);
  CHECK(!same_text_other_reason.not_signed());
  assigned = std::move(generic);
  CHECK(!assigned.not_signed() && assigned.error() == "boom");
}

void test_process_info_readers() {
  const pid_t self = ::getpid();
  const auto args = ProcessInfo::argv(self);
  const auto line = ProcessInfo::cmdline(self);
  CHECK(args && line && !args->empty());
  if (args && line) {
    std::string joined;
    for (const auto &arg : *args) {
      joined += (joined.empty() ? "" : " ") + arg;
    }
    while (!joined.empty() && joined.back() == ' ') {
      joined.pop_back();
    }
    CHECK(*line == joined); // same bytes, different presentation
  }
  CHECK(ProcessInfo::readProc(self, "status").has_value());
  CHECK(!ProcessInfo::readProc(self, "status", 8).has_value()); // too large
  CHECK(!ProcessInfo::readProc(self, "no-such-leaf").has_value());
  CHECK(!ProcessInfo::readProc(999999999, "status").has_value());
  CHECK(!ProcessInfo::cmdline(999999999).has_value());
}

void test_traced_caller() {
  const auto shell = Security::trusted_executable("/bin/sh");
  if (!shell) {
    std::printf("SKIP traced caller: /bin/sh is not a root-owned executable\n");
    return;
  }
  const pid_t pid = ::fork();
  if (pid == 0) {
    if (::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) {
      ::_exit(100);
    }
    ::execl(shell->c_str(), "sh", "-c", "sleep 10",
            static_cast<char *>(nullptr));
    ::_exit(101);
  }
  int status = 0;
  if (pid < 0 || ::waitpid(pid, &status, WUNTRACED) != pid ||
      !WIFSTOPPED(status)) {
    std::printf("SKIP traced caller: ptrace is not available here\n");
    if (pid > 0) {
      ::kill(pid, SIGKILL);
      ::waitpid(pid, nullptr, 0);
    }
    return;
  }

  AwsCliVerifier::Options options;
  options.min_ptrace_scope = 0;
  options.candidates = {"/bin/sh"};
  options.required_name = shell->filename().string();
  const auto verdict = AwsCliVerifier(options).verify(pid);
  CHECK(verdict.result == std::errc::permission_denied);
  CHECK(verdict.reason == "caller is being traced");

  ::kill(pid, SIGKILL);
  ::waitpid(pid, nullptr, 0);
}

int main() {
  if (::sodium_init() < 0) {
    std::fputs("sodium_init failed\n", stderr);
    return EXIT_FAILURE;
  }
  test_credentials();
  test_expiry_window();
  test_environment();
  test_cli_config();
  test_arguments();
  test_maps();
  test_unsafe_mappings();
  test_ptrace_scope_parse();
  test_signer_policy();
  test_output_channel();
  test_trusted_file();
  test_trust_policy();
  test_aws_defaults();
  test_pin_file_and_hash();
  test_verdict();
  test_service_install();
  test_verify();
  test_anonymous_exec_waiver();
  test_file_mapping_with_waiver();
  test_text_util();
  test_fd_io();
  test_read_trusted_file();
  test_decrypt_result();
  test_process_info_readers();
  test_traced_caller();

  std::printf("%d checks, %d failures\n", g_checks, g_failures);
  return g_failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
