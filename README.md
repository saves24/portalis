# Portalis

[English](README.md) | [简体中文](README.zh-CN.md) | [Русский](README.ru-RU.md)

## Overview

Portalis is an offline, hash-locked package manager for self-built Linux
systems. It builds a package from a pinned source archive, stores the result in
an immutable package store, and activates it through symlinks in the live
filesystem. Each installation records a numbered generation that can be
verified or rolled back.

Packages are stored under
`/usr/portalis/packages/<name>-<version>-<recipe-hash>/`. The live filesystem
contains symlinks into those directories rather than copies. `moirse rollback`
restores the package set of an earlier generation, and `moirse --verify`
compares every activated file with its recorded hash.

The manager performs no network access and does not install dependencies
automatically. Compiler flags and build arguments are supplied by the recipe.
The mechanism is summarized below.

## Features

- Each package occupies its own store directory, named after the package, its
  version, and the hash of the recipe and build environment that produced it.
  Identical inputs produce the same store path.
- The live filesystem contains symlinks into the store. Packages can therefore
  be removed, upgraded, or rolled back without modifying the files they shipped.
- Every install records a numbered generation. `moirse rollback <id>` restores
  the package set of an earlier generation; the stores required by that
  generation are retained.
- Every activated file is hashed and recorded. `moirse --verify` reports a store
  file that changed after installation and exits non-zero when it finds a
  problem.
- When a signing key is present, the build manifest is signed with a local
  Ed25519 key and checked against trusted public keys. With
  `security.require_signature = true`, an unverifiable package is refused.
- Source archives are unpacked under an unprivileged account. Build steps run
  under bubblewrap when it is available, under Landlock when it is not, and
  under the unprivileged account alone when neither mechanism is available.
  Writes are limited to the source tree, the staging directory, and directories
  declared by the recipe. The following host trees cannot be declared writable:
  `/etc`, `/usr`, `/home`, `/root`, `/var`, `/boot`, `/proc`, `/sys`, `/dev`,
  `/bin`, `/sbin`, `/lib`, `/lib32`, `/lib64`, `/libx32`, `/run`, `/opt`,
  `/srv`, `/mnt`, `/media`, and `/tmp`.
- A build reaches the network only when its recipe sets `build.network = true`.
  For an offline step, bubblewrap unshares the network and the Landlock
  fallback installs a seccomp filter that rejects INET and INET6 sockets. On
  Landlock ABI 6 and later, it also scopes abstract UNIX sockets and signals; it
  does not create PID, IPC, or network namespaces. An offline step is refused
  when the active mechanism cannot block sockets.
- Build steps run under a per-step time limit and under memory, file-size, and
  open-file ceilings. Empty configuration values select ceilings derived from
  the build host.
- Files that a running process still maps are not replaced in place. The
  transaction is staged and applied at shutdown.
- Compiled binaries and text files are rewritten so that build-host paths do not
  appear in the installed package.

## Build container

Source builds use a disposable build container. When the binary embeds a root
filesystem, Portalis unpacks it once into `/run/portalis/rootfs/<sha256>` or
`/var/lib/portalis/rootfs` with persistent caching, then starts bubblewrap with
the following view.

- `/` is the embedded root filesystem, including the static BusyBox at
  `/busybox` and `/bin/sh`;
- the host toolchain directories `/usr/bin`, `/usr/sbin`, `/usr/lib`,
  `/usr/lib32`, `/usr/lib64`, `/usr/libexec`, `/usr/include`, `/usr/share`, and
  `/usr/local` are mounted read-only;
- `/etc` and `/usr/portalis` are temporary filesystems;
- `/usr/portalis/packages` is mounted read-only;
- dependency stores are mounted read-only at `/deps/<name>`;
- the workspace and staging directory are writable;
- `/dev`, `/proc`, `/tmp`, and `/dev/shm` are fresh namespaces.

Build steps run as namespace root with all capabilities dropped. When bubblewrap
is unavailable, they run as uid/gid 65534 under Landlock. Without an embedded
root filesystem, the build uses the host read-only toolchain view instead of the
embedded root. Dependency include, library, pkg-config, CMake, and rpath paths
are added from the declared dependency stores. The component responsibilities are
summarized below.

### Component responsibilities

| Component | Responsibility |
| --- | --- |
| bubblewrap or Landlock | Provides mount, process, network, and capability isolation; it does not provide a userland or compiler. |
| Embedded rootfs | Provides the `/` base, static BusyBox and `/bin/sh`, the minimal userland, and the disposable root used by check. |
| Host toolchain mounts | Provide the compiler, linker, headers, libraries, and build utilities; these mounts are read-only. |
| Dependency stores | Provide declared build dependencies at `/deps/<name>`; their include, library, pkg-config, CMake, and rpath paths are added by the build environment. |
| Workspace and staging directory | Provide the writable build area; the embedded rootfs and package store remain read-only. |
| Package store | Provides the immutable package store mounted read-only for dependency resolution and build isolation. |

## Mechanism

1. `moirse install <archive>` resolves a recipe, or treats the archive as a
   prebuilt package when no recipe matches.
2. The archive is checked against the recipe pin, and the store path is derived
   from the recipe, host ABI, embedded rootfs, dependency stores, and confinement.
3. A source package is unpacked under an unprivileged account and built in the
   container described above. A prebuilt package skips the build steps.
4. The result is sealed in the package store with a manifest and a completion
   marker. The manifest paths, modes, hashes, and link targets are checked before
   the store is accepted.
5. Activation compares the manifest with the live tree, backs up adopted files,
   writes links into the store, and commits the activation record. Files mapped
   by a running process are staged and applied at shutdown.
6. The state database records the package, its files, and a new generation. The
   previous generation remains available for `moirse rollback`.

`moirse --verify` compares activated files with their recorded hashes and stores
with their completion markers. A signed manifest is checked against trusted
keys; `security.require_signature = true` refuses unverifiable packages.
`moirse rollback <id>` restores a generation without rebuilding the stores.
The mechanism section above summarizes the terminology and recovery flow.

## Installation

The official installer is a shell script in the release repository. It selects
the release archive for the host architecture, downloads the archive together
with its `.sha256` and `.sig` files, verifies the Ed25519 signature and the
checksum, extracts the binary, and installs it. Run the installer as root:

```sh
curl -fsSL https://raw.githubusercontent.com/saves24/portalis/master/install.sh | sudo sh
```

To pin a specific release, pass the version to the script:

```sh
curl -fsSL https://raw.githubusercontent.com/saves24/portalis/master/install.sh | sudo sh -s -- 0.1.0
```

The installer places the binary at `/usr/lib/portalis/portalis`, creates the
`/usr/bin/moirse` symlink, creates the runtime directories, and installs the
`portalis.service` systemd unit used to apply deferred activations at shutdown.
It accepts an existing local binary when invoked with a path; that path does not
download or verify a release archive.

Release archives are `.tar.gz` files named
`portalis-<version>-<target>.tar.gz`. An archive contains:

```text
portalis          static binary
install.sh        installer
LICENSE           MIT license
release.pub       release public key
```

The public key embedded in `install.sh` is the trust anchor for the download
path. The `release.pub` file inside the archive is suitable for checking internal
consistency; it is not an independent trust anchor. A downloaded archive can be
checked manually before extraction if required.

The installer handles x86_64 and aarch64 release archives. Other architectures
must be built from source. The official release binaries are statically linked
and therefore do not depend on the host C library; a locally built binary has
the linkage produced by the local toolchain.

### Installer and runtime dependencies

An installer that downloads a release requires `curl` or `wget`, `openssl`
(version 3 for Ed25519 verification), `tar`, `gzip`, and `sha256sum`. The
manager also uses `xz`, `zstd`, or `bzip2` when a package archive uses the
corresponding compression format. `bubblewrap` is optional; when it is
unavailable, build steps use the Landlock fallback described above. When neither
bubblewrap nor Landlock is available, build steps run under the unprivileged
account alone and offline steps are refused. A check command requires
`bubblewrap`; when `check.required` is false and bubblewrap is unavailable, the
check is skipped with a warning.

An installer that is given a local binary does not download a release; the
archive must therefore be verified before extraction.

### Building from source

The source tree uses the Rust toolchain pinned in `rust-toolchain.toml`:

```sh
cargo build --release --locked
```

This produces a local binary for the build host. A root filesystem image is
embedded only when `PORTALIS_ROOTFS_IMAGE` and `image/manifest.toml` are present
at build time. Official release binaries are produced by the project's release
process and are not identical to an unconfigured local build.

## Commands

| Command | Purpose |
| --- | --- |
| `moirse` | List installed packages |
| `moirse install <archive>` | Build and apply a package from an archive, or import it when no recipe matches |
| `moirse remove <package>` | Unlink a package |
| `moirse remove <package> --purge` | Unlink a package and delete its store directory |
| `moirse remove <package> --pending` | Drop a staged copy only; the installed version remains |
| `moirse remove <package> --force` | Override dependency, in-use, or busy-store refusal |
| `moirse rollback <id>` | Restore the package set recorded in a generation |
| `moirse clean [--logs] [--store] [--backups] [--yes]` | Remove old logs, unreferenced stores, stale build trees, and superseded backups |
| `moirse --show <package>` | Show one package: version, size, dependencies, dependents, and files |
| `moirse --file <path>` | Name the package that owns a path |
| `moirse --history` | List generation snapshots |
| `moirse --verify` | Compare every activated file with its recorded hash and every store with its completion marker |
| `moirse --check` | Parse every recipe and report the invalid ones |
| `moirse --orphans` | Report unreferenced stores, missing stores, and dangling links |
| `moirse --logs <package> [--tail N]` | List build logs, or print the last N lines of the newest log |
| `moirse --quiet` | Suppress progress lines during a long-running command |
| `moirse --discard-recovery` | Drop an activation or operation journal that blocks write commands, reporting each path removed |
| `moirse --version` | Print the version and the embedded root filesystem identifier, if present |

The inspection flags `--show`, `--file`, `--history`, `--orphans`, `--verify`,
`--check`, and `--logs` cannot be combined with a subcommand. `--tail` requires
`--logs`. Write commands require root. `clean` reports its plan and deletes
nothing without `--yes`.

`remove` refuses while another installed package depends on the target package;
`--force` overrides that check. `remove --purge` also refuses to delete a store
directory that a running process still maps; `--force` overrides the check.
Write commands perform housekeeping: they remove stale build directories after
one hour and prune old build logs without requiring a separate `clean`
invocation.

## Recipes

A recipe is a plain text file with one `key = value` statement per line. Keys are
flat or dotted, `#` starts a comment, lists are comma-separated, and multiline
values are written between a `<<MARKER` line and a closing `MARKER` line.

```text
# build xkbcomp from a pinned archive
package.name = xkbcomp
package.version = 1.4.7
package.depends = xkeyboard-config, libxcb

source.file = xkbcomp-1.4.7.tar.xz
source.sha256 = 0a288114e5f44e31987042c79aecff1ffad53a8154b8ec971c24a69a80f81f77

build.system = autotools
build.args = --disable-static, --with-x
build.cflags = -O2 -pipe

install.prefix = /usr
files.preserve = /etc/xkbcomp.conf
hooks.ldconfig = true
check.command = xkbcomp --version
check.timeout = 300
```

### Recipe keys

| Key | Meaning |
| --- | --- |
| `package.name` | Package name; required |
| `package.version` | Package version; required |
| `package.description` | Human-readable description; excluded from the recipe hash |
| `package.hold` | Prevent removal without `--force` |
| `package.depends` | Comma-separated package dependencies |
| `source.kind` | `source` for a source build or `binary` for a prebuilt package |
| `source.file` | Archive file name; required |
| `source.sha256` | SHA-256 of the source archive; required |
| `source.dir` | Directory inside the archive; detected automatically when empty |
| `build.system` | `autotools`, `meson`, `cargo`, or `custom`; defaults to `autotools` |
| `build.args` | Comma-separated build arguments |
| `build.cflags` | C compiler flags |
| `build.cxxflags` | C++ compiler flags |
| `build.rustflags` | Rust compiler flags |
| `build.isolation` | `rpath` to write dependency store paths into ELF runpaths |
| `build.env.<NAME>` | Additional environment variable for build steps |
| `build.network` | Allow network access during the build |
| `build.writable` | Additional host paths mounted read-write in the build sandbox |
| `build.read` | Additional host paths mounted read-only in the build sandbox |
| `build.jobs` | Parallel build jobs for this recipe |
| `build.patch` | Inline patch block; repeatable in application order |
| `install.prefix` | Installation prefix; defaults to `/usr` |
| `install.setuid` | Paths permitted to retain the setuid bit |
| `install.setgid` | `path:group` entries permitted to retain the setgid bit |
| `install.deps_ignore` | Relative path prefixes whose ELF files use a private rpath |
| `files.preserve` | Configuration paths copied once and never overwritten |
| `hooks.ldconfig` | Run `ldconfig` after activation |
| `hooks.icon_cache` | Theme directories whose icon cache is refreshed |
| `hooks.daemon_reload` | Run `systemctl daemon-reload` after activation |
| `check.command` | Command run after the build and before activation |
| `check.timeout` | Check timeout in seconds; defaults to 300 |
| `check.required` | Refuse installation when the check fails or cannot run; defaults to `false` |

Values are trimmed. Single or double quotes preserve leading or trailing
spaces, commas, and `#` characters; `\n` and `\t` are recognized inside quoted
values. A `#` outside quotes starts a comment. Unknown keys are rejected and a
key may repeat only where the format permits it, as with `build.patch`. The
`moirse --check` command validates every recipe in the recipe directory.

### Build arguments and patches

`build.args` is interpreted by the selected build system. For `autotools`, the
entries are appended to `./configure`; for `meson`, they are appended to
`meson setup`; for `cargo`, they are passed to the cargo invocation; for
`custom`, each entry is executed as a separate `sh -c` command with `DESTDIR`,
`PREFIX`, and `SRCDIR` exported. Entries are comma-separated and may be quoted
when they contain a comma. A command that contains a comma may therefore be
quoted directly or moved into a script shipped by the archive.

A patch is one block, and the key is repeated for each patch in application
order. The optional `optional = true` field skips a patch that no longer
applies:

```text
build.patch = <<PATCH
file = fix-openssl4.patch
sha256 = 9f2c...
content = <<DIFF
--- a/configure
+++ b/configure
@@ -1 +1 @@
-PKG_CHECK_MODULES(SSL, openssl)
+PKG_CHECK_MODULES(SSL, openssl >= 3.0)
DIFF
PATCH
```

### Build and check behavior

`check.command` runs after the build and before activation, inside the embedded
root filesystem, with the package and its dependencies installed in a disposable
root. The check has no host filesystem, no network, and no capabilities, and it
runs as uid 65534. A non-zero exit is a warning by default. `check.timeout`
defaults to 300 seconds. With `check.required = true`, a failed or unavailable
check refuses the installation. A build without an embedded root filesystem,
or without bubblewrap, skips the check; when `check.required = true`, the
installation is refused instead.

A source build preserves ordinary file modes. The setuid and setgid bits are
retained only for paths declared in `install.setuid` and `install.setgid`. A
setgid entry must name a group, resolved in the target root's `etc/group`; an
entry without a group, or one naming a group that is absent, refuses the
installation.

A prebuilt package declares `source.kind = binary` and has no build steps. An
archive that matches no recipe is imported as a prebuilt package: the name and
version are read from the file name, or from the control fields when the archive
is a `.deb`. An archive wrapped in a single top-level directory is refused; the
archive root must correspond to the filesystem root.

Imported archives preserve ordinary modes. A setuid or setgid bit in an imported
archive is refused unless the installation sets `PORTALIS_KEEP_PRIVILEGED=1`;
with that override, the bits are recorded in the derived recipe as
`install.setuid` or `install.setgid`. A setgid entry records the group named by
the file header; installation resolves that group in the target root and refuses
the package when the group is absent.

Build steps see the source tree, the read-only toolchain view, and dependency
stores explicitly supplied by the package metadata. Dependency include,
library, pkg-config, CMake, and rpath paths are added from those stores; a build
that requires additional headers or libraries must declare the corresponding
dependency or provide its own copies.

## Configuration

The optional configuration file is `/etc/portalis/config.port`. Missing keys
retain their defaults.

```text
security.require_signature = true

maintenance.retain_generations = 5
maintenance.backup_retention_days = 30

build.scrub_paths = true

build.jobs = 4
build.limit_memory_mb = 4096
build.limit_file_mb = 2048
build.limit_cpu_seconds = 3600
build.limit_open_files = 1024

rootfs.cache = runtime
```

| Key | Default | Meaning |
| --- | --- | --- |
| `security.require_signature` | `false` | Refuse manifests that do not verify with a trusted key; this checks local trust, not upstream provenance |
| `maintenance.retain_generations` | `5` | Number of generations retained before rollback data is reclaimed |
| `maintenance.backup_retention_days` | `30` | Age after which superseded backups may be removed |
| `build.scrub_paths` | `true` | Rewrite build-host paths from staged files |
| `build.jobs` | unset | Parallel build jobs; unset means half of the available cores |
| `build.limit_memory_mb` | unset | Address-space ceiling in MiB; unset means half of host memory |
| `build.limit_file_mb` | unset | Per-file size ceiling in MiB; unset means half of the free workspace space |
| `build.limit_cpu_seconds` | unset | CPU-time ceiling; unset means no CPU-time cap |
| `build.limit_open_files` | unset | Open-file ceiling; unset means half of the hard limit |
| `rootfs.cache` | `runtime` | `runtime` or `tmpfs` for `/run`; `persistent` for `/var/lib/portalis/rootfs` |

A value of `0` removes the corresponding resource ceiling. `build.jobs = 0`
selects the default worker count. Each build step has a separate timeout of 3600
seconds unless `PORTALIS_BUILD_TIMEOUT` specifies another positive value. A
malformed configuration aborts an installation rather than silently relaxing a
requirement.

Confinement is selected in this order: bubblewrap, Landlock, then the
unprivileged account alone. `PORTALIS_NO_BWRAP=1` skips only bubblewrap;
Landlock remains active when available. On the Landlock path, a seccomp filter
blocks INET and INET6 sockets for offline steps. No switch removes the selected
mechanism. When neither bubblewrap nor Landlock is available, an offline step is
refused because the process cannot guarantee that sockets are blocked.

The build hash includes the active confinement mechanism, the host ABI
fingerprint, the embedded rootfs digest, and dependency store paths. A recipe
therefore resolves to a different store path when those inputs differ. The
`PORTALIS_WIDE_READ` setting is ignored for build steps.

## Layout

| Path | Contents |
| --- | --- |
| `/usr/portalis/packages/` | Package stores |
| `/usr/portalis/etc/` | Per-package exposed `etc` trees |
| `/usr/portalis/appconfig/` | Machine-local build flags per package |
| `/etc/portalis/packages/*.port` | Recipes |
| `/etc/portalis/config.port` | Security, maintenance, and build options |
| `/etc/portalis/signing.key` | Local signing key, when present |
| `/etc/portalis/trusted-keys/` | Accepted public keys |
| `/var/db/portalis/db.sqlite` | Package, file, and generation database |
| `/var/lib/portalis/` | State lock, activation record, pending transaction, backups, and `last-good.json` |
| `/var/lib/portalis/backup/` | Backups of host files replaced by a transaction |
| `/var/lib/portalis/rootfs/` | Persistent rootfs cache when `rootfs.cache = persistent` |
| `/run/portalis/rootfs/` | Runtime rootfs cache when `rootfs.cache = runtime` or `tmpfs` |
| `/var/log/portalis/builds/` | Build logs |
| `/etc/systemd/system/shutdown.target.wants/portalis.service` | Unit that applies staged activations at shutdown |

A store path covers the recipe and the environment in which the build ran. A
different confinement mode, host ABI, rootfs image, dependency set, or scrub
setting produces a different directory.

## Operational notes

- Write commands modify system paths and must run as root. Use
  `PORTALIS_DRY_RUN=1 moirse install <archive>` to report the files a
  transaction would replace before it writes them.
- Before activation, every manifest path is checked. Undeclared setuid or setgid
  bits and links into protected host locations such as `/home`, `/root`,
  `/proc`, `/sys`, or `/dev` are refused.
- A package is accepted only when its manifest matches the recipe and the
  archive. With no trusted key configured, an unsigned build is accepted with a
  warning; set `security.require_signature = true` after installing trusted
  keys.
- A signing key must be owned by root and readable only by its owner
  (`chmod 600`); otherwise signing is refused.
- `security.require_signature` verifies a manifest against trusted keys. The
  signing key is local: a package signed on this host only demonstrates that this
  host processed it. It does not establish upstream provenance. Verify a package
  from an untrusted source with an independent signature or verification channel.
- Files mapped by a running process are not replaced in place. The transaction
  is staged and applied at shutdown, and `moirse` without arguments reports
  pending packages. Whether a file is in use is read from `/proc`; where that
  information is unavailable, the transaction is staged for shutdown.
- `moirse --verify` should be run after changes to the live system. It reports
  modified store files, records whose package row is absent, and activations
  that did not finish; it exits non-zero when it finds a problem.
- `rollback` restores a generation but keeps the store directories, so a
  rollback does not require a rebuild. `moirse clean --store` reclaims stores
  that no package or retained generation references.
- An archive imported without a recipe records the SHA-256 of the payload it
  installs. For a `.deb`, this is the payload member rather than the outer
  archive. The hash identifies the file; it does not authenticate it.
  `security.require_signature` checks local trusted keys; it does not establish
  that an external source produced the package.
- An imported archive that ships a setuid or setgid file is refused unless
  `PORTALIS_KEEP_PRIVILEGED=1` is set. A setgid entry records the group named by
  the file header; installation resolves that group in the target root and
  refuses the package when the group is absent.
- `--discard-recovery` removes an activation or operation journal that blocks
  write commands and reports each path it removes. It is intended for an
  operator who has inspected the journal and chosen to discard it; normal
  recovery should be allowed to complete.

## License

Portalis source is MIT. Release assets also contain BusyBox under GPL-2.0; see
`THIRD_PARTY_NOTICES.md` and `LICENSES/GPL-2.0`.
