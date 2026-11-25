#!/usr/bin/env bash
# Generate the golden backup bundles in testdata/interop/ with VaneSecret
# (Node, commit ca87d68) on a FAKE store. Development-time tool only.
#
#   tools/geninterop/geninterop.sh <VaneSecret src dir>
#
# Needs node, util-linux script and systemd-creds --user (VaneSecret's key
# backend). The bundles hold only fake values and a throwaway data key; the
# test passphrases are listed in testdata/interop/README.md.
set -euo pipefail

src=${1:?usage: geninterop.sh <VaneSecret src dir>}
src=$(cd "$src" && pwd)
repo=$(cd "$(dirname "$0")/../.." && pwd)
out="$repo/testdata/interop"
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/env/_import" "$out"
export WITH_SECRETS_ROOT="$root"
ws() { node "$src/with-secrets.mjs" "$@"; }
# Type input into a pseudo-terminal (the passphrase is read from /dev/tty).
tty() { local input=$1; shift; printf '%s' "$input" | script -qec "node $src/with-secrets.mjs $*" /dev/null; }

ws --init
cat > "$root/env/_import/interop.ini" <<'EOF'
; @desc Interop fixture: fake values only
;
; Keys:
;   HOST  server
;   PSWD  password

[n1]
; @desc Node 1 (说明)
HOST = interop.invalid
PORT = 6379
PSWD = interop-secret-1234
TOKEN = "tok ;with comment char"

[n2]
USER = alice
PSWD = 密码-ünïcode-5678
EOF
ws --import interop

ascii='interop test passphrase'
pre=$'caf\303\251 passphrase \303\251t\303\251'      # é precomposed (U+00E9 = C3 A9)
dec=$'cafe\314\201 passphrase e\314\201te\314\201'  # é decomposed (e + U+0301 = CC 81)

tty "$ascii"$'\n'"$ascii"$'\n' --backup "$root/bk-ascii"
tty "$pre"$'\n'"$pre"$'\n' --backup "$root/bk-pre" --new-password
tty "$dec"$'\n'"$dec"$'\n' --backup "$root/bk-dec" --new-password

cp "$root"/bk-ascii/secrets-base-*.wsbk "$out/node-ascii.wsbk"
cp "$root"/bk-pre/secrets-base-*.wsbk "$out/node-precomposed.wsbk"
cp "$root"/bk-dec/secrets-base-*.wsbk "$out/node-decomposed.wsbk"
chmod 644 "$out"/*.wsbk
echo "wrote $out"
