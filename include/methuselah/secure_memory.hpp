#pragma once

#include <sodium.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <limits>
#include <new>
#include <string>
#include <string_view>

#include <unistd.h>

namespace methuselah {

// libsodium must be initialised before sodium_malloc()/randombytes. This is
// idempotent and safe to call from any thread; MemoryGuard::harden() calls it
// as well, but allocators call it too so no ordering mistake can bypass it.
inline void sodium_ready() {
  static const bool ok = (::sodium_init() >= 0);
  if (!ok) {
    throw std::bad_alloc();
  }
}

inline void secure_clear(void *ptr, std::size_t n) noexcept {
  if (ptr != nullptr && n > 0) {
    ::sodium_memzero(ptr, n);
  }
}

// Allocator backed by sodium_malloc(): every allocation is placed against a
// guard page, carries a canary, is mlock()ed, excluded from core dumps
// (MADV_DONTDUMP) and zeroed by sodium_free().
template <typename T> struct SecureAllocator {
  using value_type = T;

  SecureAllocator() noexcept = default;
  template <typename U> SecureAllocator(const SecureAllocator<U> &) noexcept {}

  [[nodiscard]] T *allocate(std::size_t n) {
    if (n > std::numeric_limits<std::size_t>::max() / sizeof(T)) {
      throw std::bad_alloc();
    }
    sodium_ready();
    void *p = ::sodium_malloc(n * sizeof(T));
    if (p == nullptr) {
      throw std::bad_alloc();
    }
    return static_cast<T *>(p);
  }

  void deallocate(T *p, std::size_t) noexcept { ::sodium_free(p); }

  template <typename U> bool operator==(const SecureAllocator<U> &) const {
    return true;
  }
  template <typename U> bool operator!=(const SecureAllocator<U> &) const {
    return false;
  }
};

// std::string whose heap buffer lives in guarded, locked, non-dumpable memory.
// NOTE: short strings use the SSO buffer inside the object itself, so keep
// SecureString objects off long-lived non-secure storage and call
// secure_clear() on them as soon as the secret is no longer needed.
using SecureString =
    std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;

// Force the string onto the guarded heap. Strings of ~15 chars or fewer would
// otherwise live in the inline SSO buffer inside the (non-guarded) object.
inline void secure_reserve(SecureString &s, std::size_t n = 256) {
  s.reserve(n);
}

// Write straight to a file descriptor, bypassing iostream buffers that would
// keep an unzeroed copy of the secret. Returns false on failure.
inline bool secure_write(int fd, std::string_view data) noexcept {
  while (!data.empty()) {
    const ssize_t n = ::write(fd, data.data(), data.size());
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    data.remove_prefix(static_cast<std::size_t>(n));
  }
  return true;
}

inline void secure_clear(std::string &s) noexcept {
  if (!s.empty()) {
    ::sodium_memzero(s.data(), s.size());
    s.clear();
  }
}

inline void secure_clear(SecureString &s) noexcept {
  if (!s.empty()) {
    ::sodium_memzero(s.data(), s.size());
  }
  s.clear();
}

// Fixed-size secret buffer allocated with sodium_malloc() (guard pages,
// canary, mlock, no core dump), filled with random garbage on creation so
// uninitialised reads never expose stale memory, and zeroed on destruction.
template <std::size_t N> class SecureArray {
public:
  SecureArray() {
    sodium_ready();
    data_ = static_cast<char *>(::sodium_malloc(N));
    if (data_ == nullptr) {
      throw std::bad_alloc();
    }
    ::sodium_memzero(data_, N);
  }
  ~SecureArray() { ::sodium_free(data_); }

  SecureArray(const SecureArray &) = delete;
  SecureArray &operator=(const SecureArray &) = delete;
  SecureArray(SecureArray &&) = delete;
  SecureArray &operator=(SecureArray &&) = delete;

  [[nodiscard]] char *data() noexcept { return data_; }
  [[nodiscard]] const char *data() const noexcept { return data_; }
  [[nodiscard]] int size() const noexcept { return static_cast<int>(N); }

  // Make the buffer inaccessible (SIGSEGV on touch) while it is not in use.
  void lock_access() noexcept { ::sodium_mprotect_noaccess(data_); }
  void unlock_access() noexcept { ::sodium_mprotect_readwrite(data_); }

private:
  char *data_ = nullptr;
};

} // namespace methuselah
