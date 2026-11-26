#!/bin/sh
set -eu
umask 077

# Use a short path so GnuPG has room for its agent socket.
GNUPGHOME=$(mktemp -d /tmp/methuselah-gpg.XXXXXX)
export GNUPGHOME
cleanup() {
    gpgconf --kill gpg-agent || :
    rm -rf -- "$GNUPGHOME"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

recipient=recipient@example.invalid
signer=signer@example.invalid
passphrase=decrypt-fd-test-passphrase
run_gpg() {
    gpg --batch --no-tty --pinentry-mode loopback "$@"
}
fingerprint() {
    run_gpg --with-colons --list-keys "$1" |
        awk -F: '$1 == "fpr" { print $10; exit }'
}

run_gpg --passphrase "$passphrase" --quick-generate-key "$recipient" rsa2048 encr 0
run_gpg --passphrase '' --quick-generate-key "$signer" ed25519 sign 0
recipient_fpr=$(fingerprint "$recipient")
signer_fpr=$(fingerprint "$signer")
test -n "$recipient_fpr"
test -n "$signer_fpr"

printf 'decrypt_fd fixture plaintext\n' >"$GNUPGHOME/plaintext"
run_gpg --trust-model always --recipient "$recipient_fpr" \
    --local-user "$signer_fpr" --output "$GNUPGHOME/signed.gpg" \
    --sign --encrypt "$GNUPGHOME/plaintext"
run_gpg --trust-model always --recipient "$recipient_fpr" \
    --output "$GNUPGHOME/unsigned.gpg" --encrypt "$GNUPGHOME/plaintext"

# Clear any cached secret from key generation before testing a wrong password.
gpgconf --kill gpg-agent
"$1" "$GNUPGHOME/signed.gpg" "$GNUPGHOME/unsigned.gpg" \
    "$signer_fpr" "$recipient_fpr" "$passphrase"
