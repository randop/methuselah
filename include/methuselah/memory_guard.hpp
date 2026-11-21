#pragma once

namespace methuselah {

// Process-level memory hardening built on libsodium and Linux primitives.
//
//  * sodium_init()                  - CSPRNG + guarded allocator ready.
//  * prctl(PR_SET_DUMPABLE, 0)      - no core dumps, blocks ptrace()/gdb attach
//                                     and /proc/<pid>/mem by same-uid peers.
//  * setrlimit(RLIMIT_CORE, 0)      - belt and braces against core files.
//  * PR_SET_NO_NEW_PRIVS            - no privilege gain through exec.
//  * TracerPid check                - refuse to run if already being traced.
//  * LD_* / environment scrub       - drop loader injection variables.
//  * best-effort mlock of the stack/heap arena is intentionally NOT done with
//    mlockall(): raylib/OpenGL need large mappings that would hit
//    RLIMIT_MEMLOCK. Secrets live in sodium_malloc() memory instead, which is
//    individually locked.
class MemoryGuard {
public:
  // Returns false when a hard requirement fails (libsodium unusable or a
  // debugger/tracer is attached). Soft failures are logged and tolerated.
  [[nodiscard]] static bool harden() noexcept;

  // Overwrite a region with random bytes, then zero it. Use for scrambling
  // buffers whose previous content must not be recoverable.
  static void scramble(void *ptr, unsigned long n) noexcept;

  [[nodiscard]] static bool being_traced() noexcept;
};

} // namespace methuselah
