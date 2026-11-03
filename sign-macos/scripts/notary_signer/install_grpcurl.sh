#!/usr/bin/env bash
set -euo pipefail

# Official grpcurl v1.9.3 Linux x86_64 archive and published SHA-256.
[[ "$(uname -s)-$(uname -m)" == Linux-x86_64 ]] || {
  echo 'Notarization grpcurl requires Linux x86_64' >&2
  exit 1
}
archive="${RUNNER_TEMP}/grpcurl_1.9.3_linux_x86_64.tar.gz"
bin="${RUNNER_TEMP}/astral-notary-grpcurl-bin"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  'https://github.com/fullstorydev/grpcurl/releases/download/v1.9.3/grpcurl_1.9.3_linux_x86_64.tar.gz' -o "$archive"
echo "a926b62a85787ccf73ef8736b3ae554f1242e39d92bb8767a79d6dd23b11d1d5  $archive" | sha256sum --check
mkdir -p "$bin"
tar -xzf "$archive" -C "$bin" grpcurl
echo "$bin" >> "$GITHUB_PATH"
