#pragma once

#include <cstdint>

namespace methuselah {

enum class SecurityVerificationResult : std::uint8_t {
  passed,
  failed,
  faulted
};

class Security {
public:
  Security() = default;

  Security(const Security &) = delete;
  Security &operator=(const Security &) = delete;
  Security(Security &&) = delete;
  Security &operator=(Security &&) = delete;

  [[nodiscard]] SecurityVerificationResult verify_git() const;
};

} // namespace methuselah
