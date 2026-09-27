#!/usr/bin/env bash
# Add .deb files to a signed apt repository and regenerate its indexes.
#
#   scripts/build-apt-repo.sh <repo-dir> <deb>...
#
# <repo-dir> is the published tree (the gh-pages checkout in CI). Packages go
# to pool/main/, the index to dists/stable/main/binary-amd64/, and the signed
# Release/InRelease to dists/stable/. The signing key must already be in the
# gpg keyring; APT_KEY_ID selects it (default: the only secret key).
set -euo pipefail

repo=${1:?usage: build-apt-repo.sh <repo-dir> <deb>...}
shift
[ "$#" -gt 0 ] || { echo "no .deb files given" >&2; exit 1; }

suite=stable
component=main
arch=amd64
keep=3 # versions of each package kept in the pool

mkdir -p "$repo/pool/$component" "$repo/dists/$suite/$component/binary-$arch"
for deb in "$@"; do
    cp -f "$deb" "$repo/pool/$component/"
done

# Keep only the newest $keep versions of each package, so the pool (and the
# Pages site) does not grow without bound.
for pkg in $(for f in "$repo/pool/$component"/*.deb; do dpkg-deb -f "$f" Package; done | sort -u); do
    mapfile -t old < <(
        for f in "$repo/pool/$component"/*.deb; do
            [ "$(dpkg-deb -f "$f" Package)" = "$pkg" ] && printf '%s %s\n' "$(dpkg-deb -f "$f" Version)" "$f"
        done | sort -V -r -k1,1 | tail -n +$((keep + 1)) | cut -d' ' -f2-
    )
    for f in "${old[@]}"; do rm -f "$f"; done
done

(
    cd "$repo"
    rm -f "dists/$suite/Release" "dists/$suite/InRelease" "dists/$suite/Release.gpg"
    apt-ftparchive packages "pool/$component" > "dists/$suite/$component/binary-$arch/Packages"
    gzip -9 -k -f "dists/$suite/$component/binary-$arch/Packages"
    apt-ftparchive \
        -o "APT::FTPArchive::Release::Origin=rlm" \
        -o "APT::FTPArchive::Release::Label=rlm" \
        -o "APT::FTPArchive::Release::Suite=$suite" \
        -o "APT::FTPArchive::Release::Codename=$suite" \
        -o "APT::FTPArchive::Release::Architectures=$arch" \
        -o "APT::FTPArchive::Release::Components=$component" \
        -o "APT::FTPArchive::Release::Description=rlm: resource limits for your own processes" \
        release "dists/$suite" > "Release.tmp"
    # Written outside dists/ so the Release file does not index itself.
    mv "Release.tmp" "dists/$suite/Release"
)

key=${APT_KEY_ID:-$(gpg --list-secret-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')}
gpg --batch --yes --local-user "$key" --clearsign -o "$repo/dists/$suite/InRelease" "$repo/dists/$suite/Release"
gpg --batch --yes --local-user "$key" --armor --detach-sign -o "$repo/dists/$suite/Release.gpg" "$repo/dists/$suite/Release"
gpg --export "$key" > "$repo/rlm-archive-keyring.gpg"
# Pages would otherwise run Jekyll over the tree.
touch "$repo/.nojekyll"
echo "apt repository updated in $repo: $(ls "$repo/pool/$component" | tr '\n' ' ')"
