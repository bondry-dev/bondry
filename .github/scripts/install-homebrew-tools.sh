#!/bin/sh
set -eu

if brew tap | grep -qx 'aws/tap'; then
    brew untap aws/tap
fi

brew install "$@"
