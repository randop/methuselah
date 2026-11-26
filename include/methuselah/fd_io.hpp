#pragma once

#include <cerrno>
#include <cstddef>
#include <string>
#include <unistd.h>
#include <utility>

namespace methuselah {

// Owns a file descriptor and closes it on scope exit.
class UniqueFd {
public:
  UniqueFd() = default;
  explicit UniqueFd(int fd) noexcept : fd_(fd) {}
  ~UniqueFd() { reset(); }

  UniqueFd(const UniqueFd &) = delete;
  UniqueFd &operator=(const UniqueFd &) = delete;
  UniqueFd(UniqueFd &&other) noexcept : fd_(other.release()) {}
  UniqueFd &operator=(UniqueFd &&other) noexcept {
    if (this != &other) {
      reset(other.release());
    }
    return *this;
  }

  [[nodiscard]] int get() const noexcept { return fd_; }
  [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }
  [[nodiscard]] int release() noexcept { return std::exchange(fd_, -1); }
  void reset(int fd = -1) noexcept {
    if (fd_ >= 0) {
      ::close(fd_);
    }
    fd_ = fd;
  }

private:
  int fd_ = -1;
};

enum class ReadStatus { ok, io_error, too_large };

// The one read-until-EOF loop. Hands each chunk to `sink(const char *, size_t)`
// as it arrives; `sink` returns false to stop because the data is too large.
// Retries EINTR.
template <typename Sink>
[[nodiscard]] ReadStatus read_chunks(int fd, Sink &&sink) {
  char buffer[4096];
  for (;;) {
    const ssize_t n = ::read(fd, buffer, sizeof buffer);
    if (n > 0) {
      if (!sink(static_cast<const char *>(buffer),
                static_cast<std::size_t>(n))) {
        return ReadStatus::too_large;
      }
      continue;
    }
    if (n < 0 && errno == EINTR) {
      continue;
    }
    return n < 0 ? ReadStatus::io_error : ReadStatus::ok;
  }
}

struct ReadResult {
  ReadStatus status = ReadStatus::io_error;
  std::string data;
};

// Reads `fd` to EOF. A file of exactly `max_bytes` is accepted; one byte more
// is too_large.
[[nodiscard]] inline ReadResult read_all(int fd, std::size_t max_bytes) {
  ReadResult result;
  result.status = read_chunks(fd, [&](const char *chunk, std::size_t n) {
    if (n > max_bytes - result.data.size()) {
      return false;
    }
    result.data.append(chunk, n);
    return true;
  });
  return result;
}

} // namespace methuselah
