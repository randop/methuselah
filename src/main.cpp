#include "methuselah/application.hpp"
#include "methuselah/memory_guard.hpp"

#include <cstdlib>

int main(int argc, char **argv) {
  if (!methuselah::MemoryGuard::harden()) {
    return EXIT_FAILURE;
  }
  return methuselah::Application{}.run(argc, argv);
}
