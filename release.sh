#!/bin/bash
set -e

VERSION=$(cargo pkgid | sed -E 's/.*#([0-9]+\.[0-9]+\.[0-9]+).*/\1/')

./build.sh

rm -rf target/*.tgz target/*.tgz.sig target/release.md

create_bundle() {
    platform=$1
    arch=$2
    target_arch=$3

    echo "Creating v${VERSION} bundle for ${platform} ${arch}..."
    target="slowkey-${VERSION}-${target_arch}.tgz"
    target_sig="${target}.sig"
    release="target/${target}"
    release_sig="${release}.sig"

    tar zcvf "${release}" "target/${target_arch}/release/slowkey"
    release_sha512=$(shasum -a512 "${release}")
    gpg --output "${release_sig}" --detach-sig "${release}"

    echo "${platform}|${arch}|${target}|${target_sig}|${release}|${release_sha512}" >>/tmp/bundle_info
}

# Create bundles
create_bundle "Mac OS" "ARM64" "aarch64-apple-darwin"
create_bundle "Mac OS" "x64" "x86_64-apple-darwin"
create_bundle "Linux" "X64" "x86_64-unknown-linux-musl"
create_bundle "Linux" "ARM64" "aarch64-unknown-linux-gnu"

RELEASE_NOTES="target/release.md"
echo "Preparing release notes..."

# Start release notes
echo "# Release Notes v${VERSION}" >$RELEASE_NOTES

# Add sections for each platform
while IFS="|" read -r platform arch target target_sig release release_sha512; do
    cat <<EOF >>$RELEASE_NOTES

## ${platform} ${arch}

Calculate the SHA512:

\`\`\`sh
shasum -a512 ${release} ${release_sha512}
\`\`\`

Verify the digital signature:

\`\`\`sh
gpg --verify ${target_sig} ${target}
\`\`\`
EOF
done </tmp/bundle_info

rm /tmp/bundle_info
