#!/usr/bin/env sh
set -e

# Extract version from Cargo.toml
VERSION=$(cargo pkgid | cut -d# -f2 | cut -d: -f2)

# Run code quality checks
echo "Running audit..."
cargo audit

echo "Running clippy..."
cargo clippy --all-targets --all-features -- -D warnings

echo "Running tests..."
cargo test --release

# Build for different architectures
build_target() {
    echo "Building v${VERSION} for $1..."
    if [ "$2" = "linux-musl" ]; then
        # Set up Linux MUSL environment variables
        export CC_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-gcc
        export CXX_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-g++
        export AR_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-ar
        export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-unknown-linux-musl-gcc
    fi
    cargo build --release --target=$2
}

# Build for each target platform
build_target "Mac OS ARM64" "aarch64-apple-darwin"
build_target "Mac OS x64" "x86_64-apple-darwin"
build_target "Linux x64" "x86_64-unknown-linux-musl" "linux-musl"
