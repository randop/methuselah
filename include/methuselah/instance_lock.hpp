#pragma once

namespace methuselah {

class InstanceLock {
public:
  enum class Mode {
    // Single GUI instance: a second copy focuses the first and gives up.
    focus_existing,
    // Serialise credential_process callers: wait (up to three minutes, in no
    // guaranteed order) for the holder to finish so the next caller can reuse
    // what it unlocked instead of exiting silently. Giving up is a failure.
    wait,
  };

  explicit InstanceLock(Mode mode = Mode::focus_existing);
  ~InstanceLock();

  InstanceLock(const InstanceLock &) = delete;
  InstanceLock &operator=(const InstanceLock &) = delete;
  InstanceLock(InstanceLock &&) = delete;
  InstanceLock &operator=(InstanceLock &&) = delete;

  [[nodiscard]] bool acquired() const noexcept { return acquired_; }

private:
  int fd_ = -1;
  bool acquired_ = false;
};

} // namespace methuselah
