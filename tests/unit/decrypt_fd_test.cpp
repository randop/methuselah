#include "methuselah/fd_io.hpp"
#include "methuselah/gpg_decrypt.hpp"

#include <cstdio>
#include <cstdlib>
#include <string_view>

#include <fcntl.h>

using namespace methuselah;

namespace {

enum class Outcome { success, generic_failure, not_signed };

bool expect(const char *test, const DecryptResult &result, Outcome expected) {
  const auto actual = result.ok()           ? Outcome::success
                      : result.not_signed() ? Outcome::not_signed
                                            : Outcome::generic_failure;
  constexpr std::string_view plaintext = "decrypt_fd fixture plaintext\n";
  if (actual == expected &&
      (actual == Outcome::success ? result.plaintext() == plaintext
                                  : result.plaintext().empty())) {
    return true;
  }
  std::fprintf(stderr, "%s: unexpected outcome or plaintext (%s)\n", test,
               result.error().c_str());
  return false;
}

} // namespace

int main(int argc, char **argv) {
  if (argc != 6) {
    std::fputs(
        "Expected signed and unsigned fixtures, fingerprints and passphrase\n",
        stderr);
    return EXIT_FAILURE;
  }

  const UniqueFd signed_fd(::open(argv[1], O_RDONLY | O_CLOEXEC));
  const UniqueFd unsigned_fd(::open(argv[2], O_RDONLY | O_CLOEXEC));
  if (!signed_fd.valid() || !unsigned_fd.valid()) {
    std::perror("open encrypted fixture");
    return EXIT_FAILURE;
  }

  const GpgDecryptor decryptor;
  const SecureString passphrase(argv[5]);
  const bool wrong_passphrase = expect(
      "wrong passphrase",
      decryptor.decrypt_fd(signed_fd.get(), "wrong test passphrase", argv[3]),
      Outcome::generic_failure);
  const bool matching_signer =
      expect("retry on the same descriptor with the matching signer",
             decryptor.decrypt_fd(signed_fd.get(), passphrase, argv[3]),
             Outcome::success);
  const bool unmatched_signer =
      expect("unmatched signer",
             decryptor.decrypt_fd(signed_fd.get(), passphrase, argv[4]),
             Outcome::not_signed);
  const bool unsigned_with_policy =
      expect("unsigned message with a required signer",
             decryptor.decrypt_fd(unsigned_fd.get(), passphrase, argv[3]),
             Outcome::not_signed);
  const bool unsigned_without_policy = expect(
      "unsigned message without a required signer",
      decryptor.decrypt_fd(unsigned_fd.get(), passphrase), Outcome::success);

  return wrong_passphrase && matching_signer && unmatched_signer &&
                 unsigned_with_policy && unsigned_without_policy
             ? EXIT_SUCCESS
             : EXIT_FAILURE;
}
