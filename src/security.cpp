#include "methuselah/security.hpp"
#include "methuselah/git_helper.hpp"
#include "methuselah/process_info.hpp"
#include "methuselah/ssh_helper.hpp"

#include <spdlog/spdlog.h>

#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

namespace methuselah {

namespace {

inline bool isequals(std::string_view a, std::string_view b) noexcept {
  return a == b;
}

void report(const ProcessInfo::Entry &e, const char *label) {
  std::cerr << label << ": pid " << e.pid << " (ppid " << e.ppid << ")\n"
            << "  exe:     " << e.exe << "\n"
            << "  cmdline: " << e.cmdline << "\n";
}

} // namespace

SecurityVerificationResult Security::verify_git() const {
  const auto gitHttp = GitHelper::locateRemoteHttp();
  if (!gitHttp) {
    return SecurityVerificationResult::faulted;
  }

  const auto caller = ProcessInfo::caller();
  if (!caller) {
    std::cerr << "caller: unavailable\n";
    return SecurityVerificationResult::faulted;
  }

  SPDLOG_TRACE("caller: {}", caller->exe);
  SPDLOG_TRACE("githttp: {}", gitHttp->string());

  if (caller->exe == "<unavailable>") {
    return SecurityVerificationResult::faulted;
  }

  // Resolve both sides so symlinked install locations compare equal.
  std::error_code ec;
  const std::string callerExe =
      std::filesystem::weakly_canonical(caller->exe, ec).string();
  if (ec) {
    report(*caller, "caller");
    return SecurityVerificationResult::faulted;
  }

  const std::string helperExe =
      std::filesystem::weakly_canonical(*gitHttp, ec).string();
  if (ec) {
    return SecurityVerificationResult::faulted;
  }

  return isequals(callerExe, helperExe) ? SecurityVerificationResult::passed
                                        : SecurityVerificationResult::failed;
}

SecurityVerificationResult Security::verify_ssh() const {
  const auto sshBinary = SSHhelper::locateBinary();
  if (!sshBinary) {
    return SecurityVerificationResult::faulted;
  }

  const auto caller = ProcessInfo::caller();
  if (!caller || caller->exe == "<unavailable>") {
    return SecurityVerificationResult::faulted;
  }

  // Resolve both sides so symlinked install locations compare equal.
  std::error_code ec;
  const auto callerPath = std::filesystem::weakly_canonical(caller->exe, ec);
  if (ec) {
    return SecurityVerificationResult::faulted;
  }

  const auto sshPath = std::filesystem::weakly_canonical(*sshBinary, ec);
  if (ec) {
    return SecurityVerificationResult::faulted;
  }

  return isequals(callerPath.string(), sshPath.string())
             ? SecurityVerificationResult::passed
             : SecurityVerificationResult::failed;
}

} // namespace methuselah
