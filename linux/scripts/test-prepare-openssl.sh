#!/bin/sh
set -eu

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
prepare_script=$script_directory/prepare-openssl.sh
temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/bondry-openssl-test.XXXXXX")

cleanup() {
    rm -rf -- "$temporary_root"
}
trap cleanup EXIT HUP INT TERM

verify_metadata() {
    target=$1
    expected=$2
    actual=$($prepare_script --metadata "$target")
    if [ "$actual" != "$expected" ]; then
        printf 'Unexpected OpenSSL metadata for %s: %s\n' "$target" "$actual" >&2
        exit 1
    fi
}

verify_metadata x86_64-unknown-linux-gnu \
    '3.6.3 openssl-x86_64-linux-gnu.tar.gz 37222b62b2d6949e37ab2732cbb2e3600f916a2f59707c6ec121ed63be352beb'
verify_metadata x86_64-unknown-linux-musl \
    '3.6.3 openssl-x86_64-linux-musl.tar.gz d868a639da7befa0609d26e9719f8eb1ec633812771d766fd37505c78c72b80f'
verify_metadata aarch64-unknown-linux-gnu \
    '3.6.3 openssl-aarch64-linux-gnu.tar.gz 24995c4e37778bc2596b0fc6cb81d4e610bf9f84f6fcc6cb2e7188edfa88227c'
verify_metadata aarch64-unknown-linux-musl \
    '3.6.3 openssl-aarch64-linux-musl.tar.gz 620d5eea95c688c43f1476cc3c2602e80dd0eaf30cfedf420bf7d56476af4527'
verify_metadata riscv64gc-unknown-linux-gnu \
    '3.6.3 openssl-riscv64-linux-gnu.tar.gz 130f02fc59d8597e4889d8787776ac724cec2ec14eacdd89637c698f533c58bc'
verify_metadata riscv64gc-unknown-linux-musl \
    '3.6.3 openssl-riscv64-linux-musl.tar.gz 8ea61034e4ceb62ab04419945f93386f312c0e916994b9e86db6db3a73437265'
if $prepare_script --metadata unsupported-target >/dev/null 2>&1; then
    printf 'Unsupported OpenSSL target was accepted\n' >&2
    exit 1
fi

cache_directory=$temporary_root/cache
first_prefix=$temporary_root/first
second_prefix=$temporary_root/second
$prepare_script x86_64-unknown-linux-musl "$cache_directory" "$first_prefix" >/dev/null
test -f "$first_prefix/include/openssl/ssl.h"
test -f "$first_prefix/lib64/libcrypto.a"
test -f "$first_prefix/lib64/libssl.a"

BONDRY_OPENSSL_BASE_URL=http://127.0.0.1:1 \
    $prepare_script x86_64-unknown-linux-musl "$cache_directory" "$second_prefix" >/dev/null
cmp "$first_prefix/lib64/libcrypto.a" "$second_prefix/lib64/libcrypto.a"

if $prepare_script x86_64-unknown-linux-musl "$cache_directory" "$second_prefix" >/dev/null 2>&1; then
    printf 'Existing OpenSSL prefix was accepted\n' >&2
    exit 1
fi
