// Unit tests for the Docker credential helper: credential parsing, JSON
// rendering, server-name mapping, the Docker CLI caller verifier's pure
// checks, and verify() against a real /proc entry.
//
// Run with: meson test -C .build

#include "methuselah/docker_cli_verifier.hpp"
#include "methuselah/docker_credentials.hpp"
#include "methuselah/docker_signers.hpp"
#include "methuselah/process_info.hpp"
#include "methuselah/security.hpp"

#include <sodium.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <signal.h>
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

void test_credentials() {
  {
    const std::string text = "username=alice\npassword=s3cr3t\n";
    const auto [ec, reason, credentials] = DockerCredentials::parse(text);
    CHECK(ec == std::errc{});
    CHECK(credentials.username() == "alice");
    CHECK(credentials.secret() == "s3cr3t");
    const std::string json(
        credentials.to_credential_helper_json("https://index.docker.io/v1/"));
    CHECK(json == "{\"ServerURL\":\"https://index.docker.io/v1/\","
                  "\"Username\":\"alice\",\"Secret\":\"s3cr3t\"}\n");
  }
  {
    // Comments, CRLF, aliases, case, and separators in the key.
    const std::string text = "# registry token\r\nDOCKER_USER = alice\r\n"
                             "docker-password=s3cr3t\r\n";
    const auto [ec, reason, credentials] = DockerCredentials::parse(text);
    CHECK(ec == std::errc{});
    CHECK(credentials.username() == "alice");
    CHECK(credentials.secret() == "s3cr3t");
  }
  {
    // Quotes and backslashes must not break out of the JSON document.
    const std::string text = "username=ali\"ce\npassword=pa\\ss\"word\n";
    const auto [ec, reason, credentials] = DockerCredentials::parse(text);
    CHECK(ec == std::errc{});
    const std::string json(credentials.to_credential_helper_json("ghcr.io"));
    CHECK(
        json ==
        R"({"ServerURL":"ghcr.io","Username":"ali\"ce","Secret":"pa\\ss\"word"})"
        "\n");
  }

  CHECK(DockerCredentials::parse("").result == std::errc::invalid_argument);
  CHECK(DockerCredentials::parse("username=alice\n").result ==
        std::errc::invalid_argument);
  CHECK(DockerCredentials::parse("password=s3cr3t\n").result ==
        std::errc::invalid_argument);
  CHECK(DockerCredentials::parse("username=\npassword=s3cr3t\n").result ==
        std::errc::invalid_argument);
  CHECK(DockerCredentials::parse("username=alice\npassword=\n").result ==
        std::errc::invalid_argument);
  CHECK(DockerCredentials::parse("username=alice\npassword=s3cr3t\nextra=1\n")
            .result == std::errc::invalid_argument);
  CHECK(DockerCredentials::parse("username=alice\npassword=s3cr3t\n"
                                 "user=bob\n")
            .result == std::errc::invalid_argument);
  CHECK(DockerCredentials::parse("not a pair\n").result ==
        std::errc::invalid_argument);

  std::string control = "username=ali";
  control.push_back('\x01');
  control += "ce\npassword=s3cr3t\n";
  CHECK(DockerCredentials::parse(control).result ==
        std::errc::invalid_argument);

  std::string long_secret = "username=alice\npassword=";
  long_secret.append(4097, 'a');
  long_secret.push_back('\n');
  CHECK(DockerCredentials::parse(long_secret).result ==
        std::errc::invalid_argument);

  const auto utf8 = DockerCredentials::parse(
      "username=caf\xc3\xa9\npassword=tab\t\xe2\x82\xac\xf0\x9f\x94\x91\n");
  CHECK(utf8.result == std::errc{});
  CHECK(utf8.credentials.to_credential_helper_json("ghcr.io").find(
            R"(tab\t)"
            "\xe2\x82\xac\xf0\x9f\x94\x91") != std::string::npos);
  for (const char *bad : {"\x80", "\xc0\xaf", "\xe2\x82", "\xe2\x28\xa1",
                          "\xed\xa0\x80", "\xf4\x90\x80\x80"}) {
    CHECK(DockerCredentials::parse(std::string("username=alice\npassword=") +
                                   bad + "\n")
              .result == std::errc::invalid_argument);
  }

  // Errors must never echo secret values.
  const std::string error = std::string(
      DockerCredentials::parse("username=alice\npassword=bad\x01value\n")
          .reason);
  CHECK(error.find("bad") == std::string::npos);
}

void test_server_names() {
  CHECK(valid_docker_server("https://index.docker.io/v1/"));
  CHECK(valid_docker_server("ghcr.io"));
  CHECK(valid_docker_server("registry.example.com:5000/team"));
  CHECK(!valid_docker_server(""));
  CHECK(!valid_docker_server("bad server"));
  CHECK(!valid_docker_server("bad\nserver"));
  CHECK(valid_docker_server("[::1]"));
  CHECK(valid_docker_server("https://[2001:db8::1]:5000/v2/"));
  for (const char *bad :
       {"bad]server", "[::1", "[[::1]]", "[example.com]", "[192.0.2.1]",
        "[::1]host", "[::1]:", "[::1]:tls", "example.com/[::1]", "[::1]/path]",
        "[::1]:80[::2]"}) {
    CHECK(!valid_docker_server(bad));
  }
  CHECK(!valid_docker_server(std::string(2049, 'a')));

  const auto has = [](const std::vector<std::string> &sections,
                      std::string_view wanted) {
    return std::find(sections.begin(), sections.end(), wanted) !=
           sections.end();
  };

  const auto hub = docker_config_sections("https://index.docker.io/v1/");
  CHECK(has(hub, "docker:https://index.docker.io/v1/"));
  CHECK(has(hub, "docker:index.docker.io"));
  CHECK(has(hub, "docker:docker.io"));
  CHECK(has(hub, "docker:registry-1.docker.io"));
  CHECK(!has(hub, "docker:ghcr.io"));

  const auto ghcr = docker_config_sections("https://ghcr.io");
  CHECK(ghcr.front() == "docker:https://ghcr.io");
  CHECK(has(ghcr, "docker:ghcr.io"));
  CHECK(!has(ghcr, "docker:docker.io"));

  const auto ipv6 = docker_config_sections("https://[2001:db8::1]:5000/v2%2F/");
  CHECK(ipv6.front() == "docker-ipv6:https://%5B2001:db8::1%5D:5000/v2%252F/");
  CHECK(has(ipv6, "docker-ipv6:%5B2001:db8::1%5D:5000"));
  CHECK(has(docker_config_sections("%5B2001:db8::1%5D:5000"),
            "docker:%5B2001:db8::1%5D:5000"));

  const auto aliases = docker_server_aliases("https://index.docker.io/v1/");
  CHECK(std::find(aliases.begin(), aliases.end(), "docker.io") !=
        aliases.end());
  CHECK(std::find(aliases.begin(), aliases.end(), "index.docker.io") !=
        aliases.end());
  CHECK(docker_server_aliases("https://ghcr.io").front() == "https://ghcr.io");
}

void test_signers() {
  using S = DockerSigners;
  const std::string fpr40(40, 'a');
  const std::string fpr64(64, 'B');
  const auto entries = S::parse("# who signs what\n\nghcr.io " + fpr40 +
                                "\n  docker.io\t" + fpr64 + "  \n");
  CHECK(entries.has_value());
  if (entries) {
    CHECK(entries->size() == 2);
    const auto ghcr = S::find(*entries, "ghcr.io");
    CHECK(ghcr.passed() && ghcr.required());
    CHECK(ghcr.fingerprint == std::string(40, 'A')); // normalised
    // The Docker Hub aliases are shared with the configuration lookup.
    const auto hub = S::find(*entries, "https://index.docker.io/v1/");
    CHECK(hub.passed() && hub.required());
    CHECK(hub.fingerprint == fpr64);
    // A server without an entry is simply not enforced.
    const auto other = S::find(*entries, "registry.example.com");
    CHECK(other.passed() && !other.required());
  }
  CHECK(S::parse("").has_value() && S::parse("")->empty());
  CHECK(!S::parse("ghcr.io\n"));                               // no fingerprint
  CHECK(!S::parse("ghcr.io " + std::string(39, 'a')));         // wrong length
  CHECK(!S::parse("ghcr.io " + std::string(40, 'g')));         // not hex
  CHECK(!S::parse("ghcr.io " + fpr40 + " extra"));             // trailing junk
  CHECK(!S::parse("ghcr.io " + fpr40 + "\nghcr.io " + fpr40)); // duplicate
  // Alias spellings of the same registry would make the key ambiguous.
  CHECK(!S::parse("ghcr.io " + fpr40 + "\nhttps://ghcr.io " + fpr40));
  CHECK(!S::parse("docker.io " + fpr40 + "\nindex.docker.io " + fpr40));
  CHECK(!S::parse("bad server " + fpr40)); // invalid server
  CHECK(!S::parse("bad]server " + fpr40));
  CHECK(!S::parse(std::string(2049, 'a') + " " + fpr40));

  const auto url_entry = S::parse("https://registry.example.com/v2/ " + fpr64);
  CHECK(url_entry.has_value());
  if (url_entry) {
    CHECK(S::find(*url_entry, "registry.example.com").fingerprint == fpr64);
  }
  const S::Entries overlapping = {{"https://index.docker.io/v1/", fpr40},
                                  {"docker.io", fpr64}};
  CHECK(S::find(overlapping, "docker.io").fingerprint == fpr40);

  // An absent policy file enforces nothing.
  const auto none =
      S::load("/nonexistent/methuselah/docker-signers", "ghcr.io");
  CHECK(none.passed() && !none.required());

  // A policy file that cannot be trusted fails closed.
  char directory[] = "/tmp/methuselah-docker-policy-XXXXXX";
  if (const char *dir = ::mkdtemp(directory)) {
    const std::filesystem::path file =
        std::filesystem::path(dir) / "docker-signers";
    {
      std::ofstream out(file);
      out << "ghcr.io " << fpr40 << "\n";
    }
    const auto untrusted = S::load(file, "ghcr.io");
    CHECK(untrusted.result == std::errc::io_error && !untrusted.required());
    ::unlink(file.c_str());
    ::rmdir(dir);
  }
}

void test_environment() {
  using V = DockerCliVerifier;
  const std::string clean = std::string("HOME=/home/u") + '\0' +
                            "PATH=/usr/bin" + '\0' + "DOCKER_BUILDKIT=1" +
                            '\0' + "DOCKER_API_VERSION=1.45" + '\0';
  CHECK(!V::forbidden_environment(clean).has_value());
  CHECK(!V::forbidden_environment("").has_value());

  for (const char *bad :
       {"LD_PRELOAD=/tmp/x.so", "LD_LIBRARY_PATH=/tmp", "MALLOC_PERTURB_=1",
        "GCONV_PATH=/tmp", "GODEBUG=x509sha1=1", "SSL_CERT_FILE=/tmp/ca.pem",
        "SSL_CERT_DIR=/tmp/certs", "SSLKEYLOGFILE=/tmp/keys",
        "OPENSSL_CONF=/tmp/o.cnf", "DOCKER_CONFIG=/tmp/docker",
        "DOCKER_HOST=tcp://evil:2375", "DOCKER_CONTEXT=remote", "DOCKER_TLS=1",
        "DOCKER_TLS_VERIFY=0", "DOCKER_CERT_PATH=/tmp/certs",
        "DOCKER_AUTH_CONFIG={\"auths\":{}}",
        "DOCKER_CUSTOM_HEADERS=Authorization: x", "DOCKER_UNKNOWN=1"}) {
    const std::string env = clean + bad + '\0';
    const auto hit = V::forbidden_environment(env);
    CHECK(hit.has_value());
    if (hit) {
      CHECK(std::string(bad).starts_with(*hit));
    }
  }

  for (const char *fine :
       {"DOCKER_CLI_HINTS=false", "DOCKER_CONTENT_TRUST=1",
        "DOCKER_DEFAULT_PLATFORM=linux/amd64", "DOCKER_HIDE_LEGACY_COMMANDS=1",
        "DOCKER_SCAN_SUGGEST=false", "DOCKER_STACK_ORCHESTRATOR=swarm"}) {
    CHECK(!V::forbidden_environment(clean + fine + '\0').has_value());
  }

  // Names must match; values and look-alikes must not.
  CHECK(!V::forbidden_environment(std::string("MY_LD_PRELOAD=1") + '\0')
             .has_value());
  CHECK(!V::forbidden_environment(std::string("NOTE=LD_PRELOAD=x") + '\0')
             .has_value());
}

void test_arguments() {
  using V = DockerCliVerifier;
  CHECK(!V::forbidden_arguments({"docker", "pull", "alpine"}).has_value());
  CHECK(
      !V::forbidden_arguments({"docker", "run", "--rm", "alpine"}).has_value());
  CHECK(!V::forbidden_arguments({}).has_value());
  CHECK(!V::forbidden_arguments({"docker", "build", "--build-arg", "A=B", "."})
             .has_value());

  // Global options are parsed before the subcommand.
  for (const char *bad : {"--config",
                          "--config=/tmp",
                          "--context",
                          "--context=remote",
                          "--host",
                          "--host=tcp://evil",
                          "-H",
                          "-Htcp://evil",
                          "-c",
                          "-cremote",
                          "-c=remote",
                          "--tls",
                          "--tls=false",
                          "--tlsverify",
                          "--tlscacert=/tmp/ca",
                          "--tlscert=/tmp/cert",
                          "--tlskey=/tmp/key",
                          "--debug",
                          "--debug=false",
                          "-D",
                          "-Dl"}) {
    const auto hit = V::forbidden_arguments({"docker", bad, "pull", "alpine"});
    CHECK(hit.has_value());
    if (hit) {
      CHECK(*hit == bad);
    }
  }

  // A subcommand's own options cannot redirect the daemon, so a `-c` or
  // `--host` after the command is not a global option.
  CHECK(!V::forbidden_arguments({"docker", "pull", "-c", "foo"}).has_value());
  CHECK(!V::forbidden_arguments({"docker", "pull", "--context", "foo"})
             .has_value());
  CHECK(!V::forbidden_arguments({"docker", "run", "-c", "512", "alpine"})
             .has_value());
  CHECK(!V::forbidden_arguments({"docker", "run", "alpine", "--host", "db"})
             .has_value());
  CHECK(!V::forbidden_arguments(
             {"docker", "run", "alpine", "sh", "-c", "echo hi"})
             .has_value());
  CHECK(!V::forbidden_arguments({"docker", "--", "pull", "--host=tcp://evil"})
             .has_value());

  // -l takes a value; its value must not be mistaken for the subcommand.
  CHECK(!V::forbidden_arguments({"docker", "-l", "debug", "pull", "alpine"})
             .has_value());
  CHECK(!V::forbidden_arguments({"docker", "-l=DEBUG", "pull", "alpine"})
             .has_value());
  CHECK(V::forbidden_arguments({"docker", "-lDEBUG", "--host=remote", "pull",
                                "alpine"}) == "--host=remote");
  CHECK(!V::forbidden_arguments(
             {"docker", "--log-level", "debug", "pull", "alpine"})
             .has_value());
  CHECK(
      !V::forbidden_arguments({"docker", "--log-level=debug", "pull", "alpine"})
           .has_value());
  CHECK(V::forbidden_arguments(
            {"docker", "--log-level", "debug", "--host", "tcp://evil", "pull"})
            .has_value());
}

void test_pin_file_and_hash() {
  using V = DockerCliVerifier;
  const std::string d1(64, 'a');
  const std::string d2 =
      "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";

  auto pins = V::parse_pin_file("# docker 27.x\n\n" + d1 +
                                "  /usr/bin/docker\n" + d2 + "\n");
  CHECK(pins && pins->size() == 2);
  if (pins && pins->size() == 2) {
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
  const int pipe_result = ::pipe(fds);
  CHECK(pipe_result == 0);
  if (pipe_result != 0) {
    return;
  }
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

void test_maps() {
  using V = DockerCliVerifier;
  const std::string maps =
      "55d0c2a00000-55d0c2a21000 r--p 00000000 08:01 1310725   "
      "/usr/bin/docker\n"
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
  const auto paths = V::executable_mapping_paths(maps);
  const std::vector<std::string> expected = {
      "/memfd:libffi (deleted)", "/opt/old.so (deleted)",
      "/tmp/evil dir/lib.so", "/usr/lib/libc.so.6"};
  CHECK(paths == expected);
  CHECK(V::executable_mapping_paths("").empty());
  CHECK(V::executable_mapping_paths("garbage\n\n").empty());

  const std::string file_exec =
      "55d0-55d1 r-xp 00000000 08:01 1234  /usr/bin/docker\n";
  const std::string file_data =
      "55d1-55d2 rw-p 00001000 08:01 1234  /usr/bin/docker\n";
  const std::string anon_data = "7f00-7f10 rw-p 00000000 00:00 0 \n";
  const std::string special =
      "7ffc-7ffd r-xp 00000000 00:00 0                  [vdso]\n"
      "ff60-ff61 --xp 00000000 00:00 0                  [vsyscall]\n"
      "7f20-7f21 r-xs 00000000 00:01 77  /memfd:libffi (deleted)\n";
  CHECK(V::unsafe_mapping("") == V::UnsafeMapping::none);
  CHECK(V::unsafe_mapping(file_exec + file_data + anon_data + special) ==
        V::UnsafeMapping::none);
  CHECK(V::unsafe_mapping(file_exec + "7f30-7f31 rwxp 00000000 00:00 0 \n") ==
        V::UnsafeMapping::anonymous_writable_executable);
  CHECK(V::unsafe_mapping("7f30-7f31 rwxp 00000000 08:01 9  /usr/lib/x.so\n") ==
        V::UnsafeMapping::file_writable_executable);
  CHECK(V::unsafe_mapping(file_exec + "7f40-7f41 r-xp 00000000 00:00 0 \n") ==
        V::UnsafeMapping::anonymous_executable);
  CHECK(V::unsafe_mapping("7f40-7f41 r-xp 00000000 00:00 0\n") ==
        V::UnsafeMapping::anonymous_executable);
  CHECK(V::unsafe_mapping("7f40-7f41 r-xp 00000000 00:00\n") ==
        V::UnsafeMapping::none);
  CHECK(V::unsafe_mapping("7f40-7f41 r-xp 00000000 00:01 5  /memfd:evil "
                          "(deleted)\n") == V::UnsafeMapping::none);
}

void test_ptrace_scope_parse() {
  using V = DockerCliVerifier;
  CHECK(V::parse_ptrace_scope("0\n") == 0);
  CHECK(V::parse_ptrace_scope("1") == 1);
  CHECK(V::parse_ptrace_scope("2\n") == 2);
  CHECK(V::parse_ptrace_scope("3\n") == 3);
  for (const char *bad : {"", "\n", "4", "-1", "two", "2x", "2 2", "02x"}) {
    CHECK(!V::parse_ptrace_scope(bad).has_value());
  }
}

void test_output_channel() {
  using V = DockerCliVerifier;
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

  // Holding only the write end is not reading it.
  ::close(fds[0]);
  CHECK(V::verify_output_channel(::getpid(), fds[1]).result ==
        std::errc::permission_denied);
  ::close(fds[1]);
}

void test_defaults() {
  const auto options = DockerCliVerifier::default_options();
  CHECK(std::find(options.candidates.begin(), options.candidates.end(),
                  "/opt/methuselah/docker/docker") != options.candidates.end());
  CHECK(std::find(options.install_owners.begin(), options.install_owners.end(),
                  0) != options.install_owners.end());
  CHECK(options.pin_file == "/etc/methuselah/docker-cli.sha256");
  if (::geteuid() != 0) {
    CHECK(std::find(options.install_owners.begin(),
                    options.install_owners.end(),
                    ::geteuid()) == options.install_owners.end());
  }
}

void test_verdict() {
  const Security security;
  const auto invalid = security.verify_docker(0);
  CHECK(invalid.result == std::errc::io_error);
  CHECK(invalid.reason == "no Docker CLI parent process");

  const auto self = security.verify_docker(::getpid());
  CHECK(!self.passed());
  CHECK(!self.reason.empty());
}

struct Child {
  pid_t pid = -1;
  Child() = default;
  Child(const Child &) = delete;
  Child &operator=(const Child &) = delete;
  Child(Child &&other) noexcept : pid(std::exchange(other.pid, -1)) {}
  Child &operator=(Child &&other) noexcept {
    if (this != &other) {
      cleanup();
      pid = std::exchange(other.pid, -1);
    }
    return *this;
  }
  ~Child() { cleanup(); }

private:
  void cleanup() const {
    if (pid > 0) {
      ::kill(-pid, SIGKILL);
      ::waitpid(pid, nullptr, 0);
    }
  }
};

Child spawn(const std::string &program, std::vector<std::string> args,
            std::vector<std::string> env) {
  Child child;
  child.pid = ::fork();
  if (child.pid == 0) {
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

// The verifier must accept a root-owned executable when its options name that
// executable, and reject everything else. This exercises the /proc checks
// without needing Docker to be installed.
void test_service_install() {
  const auto sleeper = Security::trusted_executable("/bin/sleep");
  if (::geteuid() == 0 || !sleeper) {
    std::printf(
        "SKIP service install: needs a non-root caller and /bin/sleep\n");
    return;
  }

  DockerCliVerifier::Options options;
  options.min_ptrace_scope = 0;
  options.candidates = {*sleeper};
  options.required_name = sleeper->filename().string();
  options.pin_file = "/nonexistent/methuselah/docker-pin";

  Child child = spawn(sleeper->string(), {"sleep", "10"},
                      {"HOME=/nonexistent/..", "PATH=/usr/bin"});
  CHECK(wait_for_exec(child.pid, sleeper->string()));
  const auto [result, reason] = DockerCliVerifier(options).verify(child.pid);
  if (result != std::errc{}) {
    std::fprintf(stderr, "  unexpected verdict: %.*s\n",
                 static_cast<int>(reason.size()), reason.data());
  }
  CHECK(result == std::errc{});
}

} // namespace

int main() {
  if (::sodium_init() < 0) {
    std::fputs("sodium_init failed\n", stderr);
    return EXIT_FAILURE;
  }
  test_credentials();
  test_server_names();
  test_signers();
  test_environment();
  test_arguments();
  test_pin_file_and_hash();
  test_maps();
  test_ptrace_scope_parse();
  test_output_channel();
  test_defaults();
  test_verdict();
  test_service_install();

  std::printf("%d checks, %d failures\n", g_checks, g_failures);
  return g_failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
