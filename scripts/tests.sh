#!/usr/bin/env bash

# end-to-end testing tool

# exit on error, error on unset variables, and fail on pipeline errors
set -euo pipefail

# reload the GPG agent to apply the new settings
gpg-connect-agent reloadagent /bye

# test gpg passphrase pinentry
echo "test" | gpg --clearsign
