// Unit tests for the AWS credential_process helper: credential parsing, the
// AWS CLI caller verifier's pure checks, and verify() against real /proc
// state using throw-away child processes.
//
// Run with: meson test -C .build

#include "methuselah/aws_credentials.hpp"
#include "methuselah/aws_verifier.hpp"
#include "methuselah/security.hpp"

#include <sodium.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace methuselah;
using Result = SecurityVerificationResult;

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
  std::string error;
  return AwsCredentials::parse(text, error, kNow).has_value();
}

std::string parse_error(const std::string &text) {
  std::string error;
  const auto creds = AwsCredentials::parse(text, error, kNow);
  return creds ? std::string{} : error;
}

void test_credentials() {
  {
    std::string error;
    auto creds = AwsCredentials::parse(creds_text(), error, kNow);
    CHECK(creds.has_value());
    CHECK(!creds->has_session_token());
    const std::string json(creds->to_credential_process_json());
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
    std::string error;
    auto creds = AwsCredentials::parse(text, error, kNow);
    CHECK(creds.has_value());
    CHECK(creds->has_session_token());
    const std::string json(creds->to_credential_process_json());
    CHECK(json.find("\"SessionToken\":\"") != std::string::npos);
    CHECK(json.find("\"Expiration\":\"2030-01-01T00:00:00Z\"") !=
          std::string::npos);
    CHECK(json.back() == '\n');
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
  for (const char *invalid : {"2030-02-29T00:00:00Z", "2030-04-31T00:00:00Z",
                              "2030-01-01T00:00:60Z", "2030-1-01T00:00:000Z",
                              "2030-01-01T00:00:00ZZ", "2030- 1-01T00:00:00Z"}) {
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

  for (const char *bad :
       {"LD_PRELOAD=/tmp/x.so", "LD_LIBRARY_PATH=/tmp", "LD_AUDIT=/tmp/a.so",
        "PYTHONPATH=/tmp", "PYTHONSTARTUP=/tmp/s.py", "MALLOC_PERTURB_=1",
        "AWS_ENDPOINT_URL=https://evil", "AWS_ENDPOINT_URL_S3=https://evil",
        "AWS_CA_BUNDLE=/tmp/ca.pem", "SSL_CERT_FILE=/tmp/ca.pem",
        "REQUESTS_CA_BUNDLE=/tmp/ca.pem", "AWS_CONFIG_FILE=/tmp/cfg",
        "GCONV_PATH=/tmp"}) {
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

  // Names must match; look-alikes and values must not.
  CHECK(!V::forbidden_environment(std::string("MY_LD_PRELOAD=1") + '\0')
             .has_value());
  CHECK(!V::forbidden_environment(std::string("NOTE=LD_PRELOAD=x") + '\0')
             .has_value());
  CHECK(!V::forbidden_environment(std::string("AWS_PROFILE=LD_PRELOAD") + '\0')
             .has_value());
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
        "--endpoint", "--no-verify", "--deb", "export-credentials"}) {
    const auto hit = V::forbidden_arguments({"aws", "configure", bad});
    CHECK(hit.has_value());
    if (hit) {
      CHECK(*hit == bad);
    }
  }
  // Positional text after "--" is data.
  CHECK(!V::forbidden_arguments({"aws", "s3", "cp", "--", "--debug"})
             .has_value());
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

void test_verify() {
  // Stand a system shell in for `aws`: same checks, real kernel state.
  const auto shell = Security::trusted_executable("/bin/sh");
  if (!shell) {
    std::printf("SKIP verify(): /bin/sh is not a root-owned executable here\n");
    return;
  }
  AwsCliVerifier::Options options;
  options.candidates = {"/bin/sh"};
  options.required_name = shell->filename().string();
  const AwsCliVerifier verifier(options);
  const std::vector<std::string> sh_args = {"sh", "-c", "sleep 10; true"};
  const std::vector<std::string> clean_env = {"HOME=/",
                                              "AWS_PROFILE=p"};

  {
    Child ok = spawn(shell->string(), sh_args, clean_env);
    CHECK(wait_for_exec(ok.pid, shell->string()));
    const auto verdict = verifier.verify(ok.pid);
    if (verdict.result != Result::passed) {
      std::fprintf(stderr, "  unexpected verdict: %s\n",
                   verdict.reason.c_str());
    }
    CHECK(verdict.result == Result::passed);

    // A non-directory component yields ENOTDIR, not an absent pin.
    auto bad_pin = options;
    bad_pin.pin_file = "/dev/null/aws-cli.sha256";
    const auto pin_verdict = AwsCliVerifier(bad_pin).verify(ok.pid);
    CHECK(pin_verdict.result == Result::faulted);
    CHECK(pin_verdict.reason == "cannot inspect AWS CLI pin file");
  }
  {
    Child bad = spawn(shell->string(), sh_args, {"HOME=/tmp"});
    CHECK(wait_for_exec(bad.pid, shell->string()));
    const auto verdict = verifier.verify(bad.pid);
    CHECK(verdict.result == Result::failed);
    CHECK(verdict.reason.find("root controlled") != std::string::npos);
  }
  {
    auto env = clean_env;
    env.push_back("LD_PRELOAD=/tmp/evil.so");
    Child bad = spawn(shell->string(), sh_args, env);
    CHECK(wait_for_exec(bad.pid, shell->string()));
    const auto verdict = verifier.verify(bad.pid);
    CHECK(verdict.result == Result::failed);
    CHECK(verdict.reason.find("LD_PRELOAD") != std::string::npos);
  }
  {
    auto args = sh_args;
    args.push_back("--endpoint-url=http://evil");
    Child bad = spawn(shell->string(), args, clean_env);
    CHECK(wait_for_exec(bad.pid, shell->string()));
    const auto verdict = verifier.verify(bad.pid);
    CHECK(verdict.result == Result::failed);
    CHECK(verdict.reason.find("--endpoint-url") != std::string::npos);
  }
  {
    // This test binary is not the configured CLI.
    CHECK(verifier.verify(::getpid()).result == Result::failed);
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
    CHECK(verifier.verify(fake.pid).result == Result::failed);

    // Replaced on disk after start.
    ::unlink(copy.c_str());
    const auto deleted = verifier.verify(fake.pid);
    CHECK(deleted.result == Result::failed);
    ::rmdir(dir);
  }
  {
    // No usable installation at all must fault, not pass or silently fail.
    AwsCliVerifier::Options none;
    none.candidates = {"/nonexistent/aws"};
    Child ok = spawn(shell->string(), sh_args, clean_env);
    CHECK(wait_for_exec(ok.pid, shell->string()));
    CHECK(AwsCliVerifier(none).verify(ok.pid).result == Result::faulted);
  }
  {
    CHECK(verifier.verify(0).result == Result::faulted);
    CHECK(verifier.verify(1).result == Result::faulted);
  }
}

} // namespace

int main() {
  if (::sodium_init() < 0) {
    std::fputs("sodium_init failed\n", stderr);
    return EXIT_FAILURE;
  }
  test_credentials();
  test_environment();
  test_arguments();
  test_maps();
  test_trusted_file();
  test_pin_file_and_hash();
  test_verify();

  std::printf("%d checks, %d failures\n", g_checks, g_failures);
  return g_failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
