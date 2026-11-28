#!/bin/sh
set -eu
umask 022

# Install Portalis.
#
#   sh install.sh                 install the latest release for this machine
#   sh install.sh 1.2.3         install that release
#   sh install.sh ./portalis      install a binary you already have
#
# REPO and PREFIX can be overridden from the environment.

REPO=${REPO:-saves24/portalis}
PREFIX=${PREFIX:-/usr}
LIBDIR="$PREFIX/lib/portalis"
BINDIR="$PREFIX/bin"
UNITDIR=/etc/systemd/system
UNIT=portalis.service
CMD=moirse

say() { printf '%s\n' "$*"; }
die() { say "install.sh: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo sh install.sh)"

# Public half of the release signing key.
RELEASE_KEY='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAr1yGK4KJ3YlKFV+SVtKKvCeNbd8t2jPODwIgGC7fAQc=
-----END PUBLIC KEY-----'

# Report unpackers that are not installed.
missing=
for tool in gzip xz zstd bzip2; do
    command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done
if [ -n "$missing" ]; then
    say "note: unpackers missing:$missing"
    say "      an archive that uses one of them fails to import until it is installed"
fi

argument=${1:-}

tmpdir=
cleanup() {
    if [ -n "$tmpdir" ]; then rm -rf "$tmpdir"; fi
}
trap cleanup EXIT INT TERM

# -------------------------------------------------------------------- the binary
binary=
version=
if [ -n "$argument" ] && [ -f "$argument" ]; then
    [ -x "$argument" ] || die "$argument is not executable"
    binary=$argument
elif [ -n "$argument" ] && [ "$argument" != "latest" ]; then
    case $argument in
        */*|.*) die "$argument does not exist" ;;
    esac
    version=$argument
fi

if [ -z "$binary" ]; then
    command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 \
        || die "curl or wget is needed to download a release"
    command -v openssl >/dev/null 2>&1 \
        || die "openssl is needed to verify the release signature"

    fetch() {
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL "$1"
        else
            wget -qO- "$1"
        fi
    }

    host_arch=$(uname -m)
    case "$host_arch" in
        x86_64|amd64)  target=x86_64-unknown-linux-musl ;;
        aarch64|arm64) target=aarch64-unknown-linux-musl ;;
        *) die "no release for architecture $host_arch; build it from source" ;;
    esac

    if [ -z "$version" ]; then
        tag=$(fetch "https://api.github.com/repos/$REPO/releases/latest" \
              | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
        [ -n "$tag" ] || die "cannot find the latest release; pass a version instead"
        version=${tag#v}
    fi

    tmpdir=$(mktemp -d)
    base="portalis-$version-$target.tar.gz"
    url="https://github.com/$REPO/releases/download/v$version/$base"

    say "downloading $base"
    fetch "$url" > "$tmpdir/$base" || die "cannot download $url"
    fetch "$url.sha256" > "$tmpdir/$base.sha256" \
        || die "cannot download the checksum for $base"
    fetch "$url.sig" > "$tmpdir/$base.sig" \
        || die "cannot download the signature for $base"

    # Verify the signature over the checksum file, then the checksum.
    printf '%s\n' "$RELEASE_KEY" > "$tmpdir/release.pub"
    if ! openssl pkeyutl -verify -pubin -inkey "$tmpdir/release.pub" -rawin \
        -in "$tmpdir/$base.sha256" -sigfile "$tmpdir/$base.sig" >/dev/null 2>&1; then
        openssl_major=$(openssl version 2>/dev/null | sed -n 's/^OpenSSL \([0-9][0-9]*\).*/\1/p')
        if [ -n "$openssl_major" ] && [ "$openssl_major" -lt 3 ]; then
            die "checking the release signature needs OpenSSL 3 for Ed25519; this system has $openssl_major"
        fi
        die "the release signature for $base does not match the project key"
    fi

    ( cd "$tmpdir" && sha256sum -c "$base.sha256" >/dev/null 2>&1 ) \
        || die "checksum mismatch for $base"

    # Unpack without honouring the archive's owner or modes.
    if ! tar --no-same-owner --no-same-permissions -xzf "$tmpdir/$base" -C "$tmpdir" 2>/dev/null; then
        say "warning: this tar does not support --no-same-owner; unpacking without that hardening"
        tar -xzf "$tmpdir/$base" -C "$tmpdir" || die "cannot unpack $base"
    fi
    binary="$tmpdir/portalis"
    [ -f "$binary" ] && [ ! -L "$binary" ] \
        || die "the archive does not contain a portalis binary"
    [ -x "$binary" ] || die "the archived portalis is not executable"
fi

# -------------------------------------------------------------------- the layout
install -d "$LIBDIR" "$BINDIR" "$UNITDIR" \
    /etc/portalis/packages /etc/portalis/trusted-keys \
    /var/lib/portalis /var/db/portalis /var/log/portalis/builds \
    /usr/portalis/packages /usr/portalis/appconfig /usr/portalis/etc

# Recipes and ledger 0750; the state directory 0751.
chmod 750 /etc/portalis /var/db/portalis
chmod 751 /var/lib/portalis

# Install beside the target, then move it into place.
install -m755 "$binary" "$LIBDIR/.portalis.new"
mv -f "$LIBDIR/.portalis.new" "$LIBDIR/portalis"
ln -sf "$LIBDIR/portalis" "$BINDIR/$CMD"

"$LIBDIR/portalis" --version >/dev/null 2>&1 \
    || die "the installed binary does not run on this machine"

cat > "$UNITDIR/$UNIT" <<EOF
[Unit]
Description=Portalis package activation
DefaultDependencies=no
After=local-fs.target
Before=shutdown.target reboot.target halt.target kexec.target

[Service]
Type=oneshot
Environment=PORTALIS_APPLY_PENDING=1
ExecStart="$LIBDIR/portalis"
TimeoutStartSec=600
RemainAfterExit=yes

[Install]
WantedBy=shutdown.target
EOF

# Enable the unit only for the system unit directory.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    # Enable the unit; a failure is a warning.
    systemctl enable "$UNIT" || say "warning: could not enable $UNIT"
fi

say "installed $LIBDIR/portalis"
say "version   $("$LIBDIR/portalis" --version | head -1)"
say "command   $BINDIR/$CMD"
say "next      $CMD install <archive>"
