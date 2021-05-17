#!/usr/bin/env sh

# The $PATH used by Xcode likely won't contain Cargo, fix that.
# This assumes a default `rustup` setup.
export PATH="$HOME/.cargo/bin:$PATH"

# --xcode-integ determines --release and --targets from Xcode's env vars.
# Depending your setup, specify the rustup toolchain explicitly.
cargo lipo --xcode-integ