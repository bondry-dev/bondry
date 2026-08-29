#!/bin/sh
set -eu

version=3.6.3
base_url=${BONDRY_OPENSSL_BASE_URL:-https://github.com/cocoa-xu/openssl-build/releases/download/v$version}

resolve_target() {
    case "$1" in
        x86_64-unknown-linux-gnu)
            triplet=x86_64-linux-gnu
            archive_sha256=37222b62b2d6949e37ab2732cbb2e3600f916a2f59707c6ec121ed63be352beb
            ;;
        x86_64-unknown-linux-musl)
            triplet=x86_64-linux-musl
            archive_sha256=d868a639da7befa0609d26e9719f8eb1ec633812771d766fd37505c78c72b80f
            ;;
        aarch64-unknown-linux-gnu)
            triplet=aarch64-linux-gnu
            archive_sha256=24995c4e37778bc2596b0fc6cb81d4e610bf9f84f6fcc6cb2e7188edfa88227c
            ;;
        aarch64-unknown-linux-musl)
            triplet=aarch64-linux-musl
            archive_sha256=620d5eea95c688c43f1476cc3c2602e80dd0eaf30cfedf420bf7d56476af4527
            ;;
        riscv64gc-unknown-linux-gnu)
            triplet=riscv64-linux-gnu
            archive_sha256=130f02fc59d8597e4889d8787776ac724cec2ec14eacdd89637c698f533c58bc
            ;;
        riscv64gc-unknown-linux-musl)
            triplet=riscv64-linux-musl
            archive_sha256=8ea61034e4ceb62ab04419945f93386f312c0e916994b9e86db6db3a73437265
            ;;
        *)
            printf 'Unsupported OpenSSL target: %s\n' "$1" >&2
            exit 64
            ;;
    esac
    archive_name=openssl-$triplet.tar.gz
}

verify_archive() {
    printf '%s  %s\n' "$archive_sha256" "$1" | sha256sum --check --status
}

if [ "$#" -eq 2 ] && [ "$1" = --metadata ]; then
    resolve_target "$2"
    printf '%s %s %s\n' "$version" "$archive_name" "$archive_sha256"
    exit 0
fi

if [ "$#" -ne 3 ]; then
    printf 'usage: %s <rust-target> <cache-directory> <prefix>\n' "$0" >&2
    exit 64
fi
if [ "$(uname -s)" != Linux ]; then
    printf 'Precompiled OpenSSL preparation requires Linux\n' >&2
    exit 69
fi

resolve_target "$1"
cache_directory=$2
prefix=$3
archive_path=$cache_directory/$archive_name
download_path=
staging_directory=

cleanup() {
    if [ -n "$download_path" ]; then
        rm -f -- "$download_path"
    fi
    if [ -n "$staging_directory" ]; then
        rm -rf -- "$staging_directory"
    fi
}
trap cleanup EXIT HUP INT TERM

if [ -e "$prefix" ]; then
    printf 'OpenSSL prefix already exists: %s\n' "$prefix" >&2
    exit 73
fi

mkdir -p "$cache_directory"
if [ -f "$archive_path" ] && ! verify_archive "$archive_path"; then
    rm -f -- "$archive_path"
fi
if [ ! -f "$archive_path" ]; then
    download_path=$(mktemp "$cache_directory/.$archive_name.XXXXXX")
    curl \
        --fail \
        --location \
        --retry 3 \
        --retry-all-errors \
        --silent \
        --show-error \
        --output "$download_path" \
        "$base_url/$archive_name"
    if ! verify_archive "$download_path"; then
        printf 'OpenSSL archive checksum mismatch: %s\n' "$archive_name" >&2
        exit 65
    fi
    chmod 0644 "$download_path"
    mv "$download_path" "$archive_path"
    download_path=
fi

mkdir -p "$(dirname "$prefix")"
staging_directory=$(mktemp -d "$(dirname "$prefix")/.openssl.XXXXXX")
tar -xzf "$archive_path" -C "$staging_directory"
if [ ! -f "$staging_directory/include/openssl/ssl.h" ]; then
    printf 'OpenSSL archive is missing public headers\n' >&2
    exit 65
fi
if [ -f "$staging_directory/lib/libcrypto.a" ] && [ -f "$staging_directory/lib/libssl.a" ]; then
    :
elif [ -f "$staging_directory/lib64/libcrypto.a" ] && [ -f "$staging_directory/lib64/libssl.a" ]; then
    :
else
    printf 'OpenSSL archive is missing static libraries\n' >&2
    exit 65
fi

mv "$staging_directory" "$prefix"
staging_directory=
printf '%s\n' "$prefix"
