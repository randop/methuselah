#include "methuselah/gpg_decrypt.hpp"

#include <cctype>
#include <cerrno>
#include <gpgme.h>
#include <string>
#include <string_view>
#include <unistd.h>

namespace methuselah {
namespace {

gpgme_error_t passphrase_callback(void *hook, const char * /*uid_hint*/,
                                  const char * /*passphrase_info*/,
                                  int /*prev_was_bad*/, int fd) {
  const auto *passphrase = static_cast<const SecureString *>(hook);
  SecureString with_newline;
  secure_reserve(with_newline, passphrase->size() + 2);
  with_newline.assign(*passphrase);
  with_newline.push_back('\n');
  const char *ptr = with_newline.c_str();
  std::size_t remaining = with_newline.size();
  gpgme_error_t result = GPG_ERR_NO_ERROR;
  while (remaining > 0) {
    ssize_t written = write(fd, ptr, remaining);
    if (written < 0) {
      result = gpgme_error_from_errno(errno);
      break;
    }
    ptr += written;
    remaining -= static_cast<std::size_t>(written);
  }
  secure_clear(with_newline);
  return result;
}

class GpgmeContext {
public:
  GpgmeContext() { err_ = gpgme_new(&ctx_); }
  ~GpgmeContext() {
    if (ctx_ != nullptr) {
      gpgme_release(ctx_);
    }
  }

  GpgmeContext(const GpgmeContext &) = delete;
  GpgmeContext &operator=(const GpgmeContext &) = delete;
  GpgmeContext(GpgmeContext &&) = delete;
  GpgmeContext &operator=(GpgmeContext &&) = delete;

  [[nodiscard]] bool ok() const noexcept { return ctx_ != nullptr && !err_; }
  [[nodiscard]] gpgme_error_t error() const noexcept { return err_; }
  [[nodiscard]] gpgme_ctx_t get() const noexcept { return ctx_; }

private:
  gpgme_ctx_t ctx_ = nullptr;
  gpgme_error_t err_ = 0;
};

class GpgmeData {
public:
  GpgmeData() = default;
  ~GpgmeData() {
    if (data_ != nullptr) {
      gpgme_data_release(data_);
    }
  }

  GpgmeData(const GpgmeData &) = delete;
  GpgmeData &operator=(const GpgmeData &) = delete;
  GpgmeData(GpgmeData &&) = delete;
  GpgmeData &operator=(GpgmeData &&) = delete;

  [[nodiscard]] gpgme_error_t from_file(const char *path) {
    return gpgme_data_new_from_file(&data_, path, 1);
  }

  [[nodiscard]] gpgme_error_t from_fd(int fd) {
    return gpgme_data_new_from_fd(&data_, fd);
  }

  [[nodiscard]] gpgme_error_t create() { return gpgme_data_new(&data_); }

  [[nodiscard]] gpgme_data_t get() const noexcept { return data_; }

private:
  gpgme_data_t data_ = nullptr;
};

bool same_fingerprint(const char *actual, std::string_view required) {
  if (actual == nullptr) {
    return false;
  }
  const std::string_view have(actual);
  if (have.size() != required.size()) {
    return false;
  }
  for (std::size_t i = 0; i < have.size(); ++i) {
    if (std::toupper(static_cast<unsigned char>(have[i])) !=
        std::toupper(static_cast<unsigned char>(required[i]))) {
      return false;
    }
  }
  return true;
}

// True only when every signature on the message is good and at least one is
// made by `required` (the signing key itself or the primary key it belongs
// to). Trust in the key is not consulted: the caller pinned the fingerprint.
bool signed_by(gpgme_ctx_t ctx, std::string_view required) {
  const gpgme_verify_result_t verdict = gpgme_op_verify_result(ctx);
  if (verdict == nullptr || verdict->signatures == nullptr) {
    return false;
  }
  bool matched = false;
  for (gpgme_signature_t sig = verdict->signatures; sig != nullptr;
       sig = sig->next) {
    if (gpgme_err_code(sig->status) != GPG_ERR_NO_ERROR) {
      return false;
    }
    if (same_fingerprint(sig->fpr, required)) {
      matched = true;
      continue;
    }
    if (sig->fpr == nullptr) {
      continue;
    }
    // A signing subkey: compare its primary key. A separate context keeps the
    // verification result above intact.
    GpgmeContext lookup;
    gpgme_key_t key = nullptr;
    if (lookup.ok() &&
        gpgme_get_key(lookup.get(), sig->fpr, &key, 0) == GPG_ERR_NO_ERROR &&
        key != nullptr) {
      if (key->subkeys != nullptr &&
          same_fingerprint(key->subkeys->fpr, required)) {
        matched = true;
      }
      gpgme_key_unref(key);
    }
  }
  return matched;
}

template <typename OpenCipher>
DecryptResult decrypt(const SecureString &passphrase, OpenCipher open_cipher,
                      std::string_view required_signer = {}) {
  DecryptResult result;

  gpgme_check_version(nullptr);

  GpgmeContext ctx;
  if (!ctx.ok()) {
    result.set_error(gpgme_strerror(ctx.error()));
    return result;
  }

  gpgme_set_protocol(ctx.get(), GPGME_PROTOCOL_OpenPGP);
  gpgme_set_armor(ctx.get(), 0);
  gpgme_set_pinentry_mode(ctx.get(), GPGME_PINENTRY_MODE_LOOPBACK);
  gpgme_set_passphrase_cb(ctx.get(), passphrase_callback,
                          const_cast<SecureString *>(&passphrase));

  GpgmeData cipher;
  gpgme_error_t err = open_cipher(cipher);
  if (err) {
    result.set_error(gpgme_strerror(err));
    return result;
  }

  GpgmeData plain;
  err = plain.create();
  if (err) {
    result.set_error(gpgme_strerror(err));
    return result;
  }

  const bool verify = !required_signer.empty();
  err = verify ? gpgme_op_decrypt_verify(ctx.get(), cipher.get(), plain.get())
               : gpgme_op_decrypt(ctx.get(), cipher.get(), plain.get());
  if (err) {
    result.set_error(gpgme_strerror(err));
    return result;
  }
  if (verify && !signed_by(ctx.get(), required_signer)) {
    result.set_error(GpgDecryptor::kNotSignedError);
    return result;
  }

  gpgme_data_seek(plain.get(), 0, SEEK_SET);
  char buf[4096];
  ssize_t n = 0;
  SecureString plaintext;
  secure_reserve(plaintext, 4096);
  while ((n = gpgme_data_read(plain.get(), buf, sizeof(buf))) > 0) {
    plaintext.append(buf, static_cast<std::size_t>(n));
  }
  secure_clear(buf, sizeof(buf));
  result.set_plaintext(std::move(plaintext));
  return result;
}

} // namespace

DecryptResult GpgDecryptor::decrypt_file(const std::filesystem::path &gpg_path,
                                         const SecureString &passphrase) const {
  return decrypt(passphrase, [&](GpgmeData &cipher) {
    return cipher.from_file(gpg_path.c_str());
  });
}

DecryptResult GpgDecryptor::decrypt_fd(int fd, const SecureString &passphrase,
                                       std::string_view required_signer) const {
  if (::lseek(fd, 0, SEEK_SET) == -1) {
    DecryptResult result;
    result.set_error("cannot rewind encrypted credentials");
    return result;
  }
  return decrypt(
      passphrase, [&](GpgmeData &cipher) { return cipher.from_fd(fd); },
      required_signer);
}

} // namespace methuselah
