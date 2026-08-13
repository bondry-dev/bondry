#!/bin/sh
set -eu

version=v0.11.0

case "$(uname -sm)" in
    "Darwin arm64")
        platform=darwin.aarch64
        checksum=56affdd8de5527894dca6dc3d7e0a99a873b0f004d7aabc30ae407d3f48b0a79
        ;;
    "Darwin x86_64")
        platform=darwin.x86_64
        checksum=3c89db4edcab7cf1c27bff178882e0f6f27f7afdf54e859fa041fca10febe4c6
        ;;
    *)
        printf 'Unsupported ShellCheck host: %s\n' "$(uname -sm)" >&2
        exit 1
        ;;
esac

archive="${RUNNER_TEMP:?}/shellcheck-${version}.tar.xz"
install_directory="${RUNNER_TEMP:?}/shellcheck-${version}"
url="https://github.com/koalaman/shellcheck/releases/download/${version}/shellcheck-${version}.${platform}.tar.xz"

curl --fail --location --retry 3 --silent --show-error --output "$archive" "$url"
printf '%s  %s\n' "$checksum" "$archive" | shasum -a 256 --check
mkdir -p "$install_directory"
tar -xJf "$archive" -C "$install_directory" --strip-components=1
printf '%s\n' "$install_directory" >> "${GITHUB_PATH:?}"
"$install_directory/shellcheck" --version
