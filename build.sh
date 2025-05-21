#!/usr/bin/env sh
set -e

# Extract version from Cargo.toml
VERSION=$(cargo pkgid | cut -d# -f2 | cut -d: -f2)

# Run code quality checks
echo "Running audit..."
cargo audit

# echo "Running clippy..."
cargo clippy --all-targets --all-features -- -D warnings

# echo "Running tests..."
cargo test --release

# Build for different architectures
build_target() {
    echo "Building v${VERSION} for $1..."
    if [ "$2" = "x86_64-unknown-linux-gnu" ]; then
        CROSS_CONTAINER_OPTS="--platform linux/amd64" cross build --release --target="$2"
    elif [ "$2" = "aarch64-unknown-linux-gnu" ]; then
        # Set up environment variables for ARM64 Linux cross-compilation
        export CC_aarch64_unknown_linux_gnu=aarch64-unknown-linux-gnu-gcc
        export CXX_aarch64_unknown_linux_gnu=aarch64-unknown-linux-gnu-g++
        export AR_aarch64_unknown_linux_gnu=aarch64-unknown-linux-gnu-ar
        export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-unknown-linux-gnu-gcc
        cargo build --release --target="$2"
    else
        cargo build --release --target="$2"
    fi
}

# Build for each target platform
build_target "Mac OS ARM64" "aarch64-apple-darwin"
build_target "Mac OS x64" "x86_64-apple-darwin"
build_target "Linux x64" "x86_64-unknown-linux-gnu" "linux-gnu"
build_target "Linux ARM64" "aarch64-unknown-linux-gnu" "linux-gnu"
