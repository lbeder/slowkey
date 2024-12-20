#!/usr/bin/env sh
set -e

VERSION=$(cargo pkgid | sed -E 's/.*#([0-9]+\.[0-9]+\.[0-9]+).*/\1/')

./build.sh

rm -rf target/*.tgz target/*.tgz.sig target/release.md

echo "Creating v${VERSION} bundle for Mac OS ARM64..."
APPLE_ARM64_TARGET="slowkey-${VERSION}-osx-arm64.tgz"
APPLE_ARM64_TARGET_SIG=${APPLE_ARM64_TARGET}.sig
APPLE_ARM64_RELEASE="target/${APPLE_ARM64_TARGET}"
APPLE_ARM64_RELEASE_SIG=${APPLE_ARM64_RELEASE}.sig
tar zcvf ${APPLE_ARM64_RELEASE} target/aarch64-apple-darwin/release/slowkey
APPLE_ARM64_RELEASE_SHA512=$(shasum -a512 ${APPLE_ARM64_RELEASE})
gpg --output ${APPLE_ARM64_RELEASE_SIG} --detach-sig ${APPLE_ARM64_RELEASE}

echo "Creating v${VERSION} bundle for Mac OS x64..."
APPLE_X64_TARGET="slowkey-${VERSION}-osx-x64.tgz"
APPLE_X64_TARGET_SIG=${APPLE_X64_TARGET}.sig
APPLE_X64_RELEASE="target/${APPLE_X64_TARGET}"
APPLE_X64_RELEASE_SIG=${APPLE_X64_RELEASE}.sig
tar zcvf ${APPLE_X64_RELEASE} target/x86_64-apple-darwin/release/slowkey
APPLE_X64_RELEASE_SHA512=$(shasum -a512 ${APPLE_X64_RELEASE})
gpg --output ${APPLE_X64_RELEASE_SIG} --detach-sig ${APPLE_X64_RELEASE}

echo "Creating v${VERSION} bundle for Linux X64..."
LINUX_X64_TARGET="slowkey-${VERSION}-linux-x64.tgz"
LINUX_X64_TARGET_SIG=${LINUX_X64_TARGET}.sig
LINUX_X64_RELEASE="target/${LINUX_X64_TARGET}"
LINUX_X64_RELEASE_SIG=${LINUX_X64_RELEASE}.sig
tar zcvf ${LINUX_X64_RELEASE} target/x86_64-unknown-linux-musl/release/slowkey
LINUX_X64_RELEASE_SHA512=$(shasum -a512 ${LINUX_X64_RELEASE})
gpg --output ${LINUX_X64_RELEASE_SIG} --detach-sig ${LINUX_X64_RELEASE}

RELEASE_NOTES="target/release.md"
echo "Preparing release notes..."

cat <<EOF >$RELEASE_NOTES
# Release Notes v${VERSION}

## Mac OS ARM64

Calculate the SHA512:

\`\`\`sh
shasum -a512 ${APPLE_ARM64_RELEASE} ${APPLE_ARM64_RELEASE_SHA512}
\`\`\`

Verify the digital signature:

\`\`\`sh
gpg --verify ${APPLE_ARM64_TARGET_SIG} ${APPLE_ARM64_TARGET}
\`\`\`

## Mac OS x64

Calculate the SHA512:

\`\`\`sh
shasum -a512 ${APPLE_X64_RELEASE} ${APPLE_X64_RELEASE_SHA512}
\`\`\`

Verify the digital signature:

\`\`\`sh
gpg --verify ${APPLE_X64_TARGET_SIG} ${APPLE_X64_TARGET}
\`\`\`

## Linux X64

Calculate the SHA512:

\`\`\`sh
shasum -a512 ${LINUX_X64_RELEASE} ${LINUX_X64_RELEASE_SHA512}
\`\`\`

Verify the digital signature:

\`\`\`sh
gpg --verify ${LINUX_X64_TARGET_SIG} ${LINUX_X64_TARGET}
\`\`\`

EOF
