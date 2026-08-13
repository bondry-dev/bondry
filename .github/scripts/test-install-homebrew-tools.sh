#!/bin/sh
set -eu

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/bondry-homebrew-test.XXXXXX")
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

cat > "$temporary_directory/brew" <<'EOF'
#!/bin/sh
set -eu

printf '%s\n' "$*" >> "$BREW_CALLS"
case "$1" in
    tap)
        printf '%s\n' "${BREW_TAPS:-}"
        ;;
    untap | install)
        ;;
    *)
        exit 1
        ;;
esac
EOF
chmod +x "$temporary_directory/brew"

BREW_CALLS="$temporary_directory/with-tap.calls" \
BREW_TAPS='aws/tap' \
PATH="$temporary_directory:$PATH" \
    sh "$script_directory/install-homebrew-tools.sh" actionlint

cat > "$temporary_directory/with-tap.expected" <<'EOF'
tap
untap aws/tap
install actionlint
EOF
cmp "$temporary_directory/with-tap.expected" "$temporary_directory/with-tap.calls"

BREW_CALLS="$temporary_directory/without-tap.calls" \
BREW_TAPS='' \
PATH="$temporary_directory:$PATH" \
    sh "$script_directory/install-homebrew-tools.sh" gh jq

cat > "$temporary_directory/without-tap.expected" <<'EOF'
tap
install gh jq
EOF
cmp "$temporary_directory/without-tap.expected" "$temporary_directory/without-tap.calls"
