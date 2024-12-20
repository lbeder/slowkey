#!/usr/bin/env sh
set -e

VERSION=$(cargo pkgid | cut -d# -f2 | cut -d: -f2)

echo "Running audit..."
cargo audit

echo "Running clippy..."
cargo clippy --all-targets --all-features -- -D warnings

echo "Running tests..."
cargo test --release

echo "Building v${VERSION} for Mac OS ARM64..."
cargo build --release --target=aarch64-apple-darwin

echo "Building v${VERSION} for Mac OS x64..."
cargo build --release --target=x86_64-apple-darwin

echo "Building v${VERSION} for Linux x64..."
export CC_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-gcc
export CXX_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-g++
export AR_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-ar
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-unknown-linux-musl-gcc
cargo build --release --target=x86_64-unknown-linux-musl
