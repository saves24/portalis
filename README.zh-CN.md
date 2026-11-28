# Portalis

[English](README.md) | [简体中文](README.zh-CN.md) | [Русский](README.ru-RU.md)

## 概述

Portalis 是面向自建 Linux 系统的离线、哈希锁定软件包管理器。它从固定的源码归档构建软件包，将产物保存在不可变包存储中，并通过活动文件系统中的符号链接完成激活。每次安装都会记录一个带编号的 generation，该 generation 可以校验或回滚。

软件包存储在
`/usr/portalis/packages/<name>-<version>-<recipe-hash>/`。活动文件系统包含指向这些目录的符号链接，而不是文件副本。`moirse rollback` 恢复早期 generation 的软件包集合，`moirse --verify` 将每个已激活文件与其记录的哈希进行比较。

管理器不访问网络，也不会自动安装依赖。编译参数和构建参数由 recipe 提供。相关机制在下方概述。

## 特性

- 每个软件包占用独立的存储目录，目录名包含软件包名、版本，以及生成该产物的 recipe 与构建环境哈希。相同输入产生相同的存储路径。
- 活动文件系统包含指向存储的符号链接。因此，删除、升级或回滚软件包不需要修改其已发布的文件。
- 每次安装记录一个带编号的 generation。`moirse rollback <id>` 恢复早期 generation 的软件包集合，该 generation 所需的存储会继续保留。
- 每个已激活文件都会计算哈希并记录。`moirse --verify` 报告安装后发生变化的存储文件，并在发现问题时以非零状态退出。
- 存在签名密钥时，构建 manifest 会使用本地 Ed25519 密钥签名，并与受信公钥进行校验。设置
  `security.require_signature = true` 后，无法验证的软件包会被拒绝。
- 源码归档在非特权账户下解包。构建步骤在 bubblewrap 可用时运行于 bubblewrap，否则运行于 Landlock；两者均不可用时，仅以非特权账户运行。写入范围限于源码树、暂存目录和 recipe 声明的目录。以下宿主目录不能声明为可写：
  `/etc`、`/usr`、`/home`、`/root`、`/var`、`/boot`、`/proc`、`/sys`、`/dev`、
  `/bin`、`/sbin`、`/lib`、`/lib32`、`/lib64`、`/libx32`、`/run`、`/opt`、
  `/srv`、`/mnt`、`/media` 和 `/tmp`。
- 仅当 recipe 设置 `build.network = true` 时，构建才可访问网络。对于离线步骤，bubblewrap 会隔离网络，Landlock 回退路径会安装 seccomp 过滤器，拒绝 INET 和 INET6 套接字。Landlock ABI 6 及更高版本还会隔离抽象 UNIX 套接字和信号；它不会创建 PID、IPC 或网络命名空间。若当前机制无法阻断套接字，离线步骤会被拒绝。
- 构建步骤受单步时间限制，并受内存、单文件大小和打开文件数上限约束。配置为空时，使用根据构建主机推导的上限。
- 运行中进程仍映射的文件不会被原地替换。相关事务会暂存，并在关机时应用。
- 编译产物和文本文件会被重写，以避免构建主机路径进入已安装软件包。

## 构建容器

源码构建使用一次性构建容器。二进制嵌入 rootfs 时，Portalis 会将其解包到
`/run/portalis/rootfs/<sha256>`，或使用持久缓存
`/var/lib/portalis/rootfs`，然后以以下视图启动 bubblewrap。

- `/` 为嵌入 rootfs，包含静态 BusyBox `/busybox` 和 `/bin/sh`；
- 宿主工具链目录 `/usr/bin`、`/usr/sbin`、`/usr/lib`、`/usr/lib32`、
  `/usr/lib64`、`/usr/libexec`、`/usr/include`、`/usr/share` 和
  `/usr/local` 以只读方式挂载；
- `/etc` 和 `/usr/portalis` 为临时文件系统；
- `/usr/portalis/packages` 以只读方式挂载；
- 依赖存储以只读方式挂载到 `/deps/<name>`；
- 工作区和暂存目录可写；
- `/dev`、`/proc`、`/tmp` 和 `/dev/shm` 为全新命名空间。

构建步骤以命名空间 root 身份运行，并丢弃全部 capability。bubblewrap 不可用时，
构建步骤在 Landlock 下以 uid/gid 65534 运行。没有嵌入 rootfs 时，构建使用宿主
只读工具链视图，而不是嵌入 root。依赖的 include、library、pkg-config、CMake
和 rpath 路径会根据声明的依赖存储加入。组件职责见下表。

### 组件职责

| 组件 | 职责 |
| --- | --- |
| bubblewrap 或 Landlock | 提供挂载、进程、网络和 capability 隔离；不提供 userland 或编译器。 |
| 嵌入 rootfs | 提供 `/` 基础、静态 BusyBox 与 `/bin/sh`、最小 userland，以及 check 使用的一次性根。 |
| 宿主工具链挂载 | 提供编译器、链接器、头文件、库和构建工具；这些挂载为只读。 |
| 依赖存储 | 在 `/deps/<name>` 提供已声明的构建依赖；其 include、library、pkg-config、CMake 与 rpath 路径由构建环境加入。 |
| 工作区与暂存目录 | 提供可写构建区域；嵌入 rootfs 与包存储保持只读。 |
| 包存储 | 以只读方式提供不可变包存储，用于依赖解析与构建隔离。 |

## 机制详解

1. `moirse install <archive>` 解析 recipe；若没有匹配的 recipe，则将归档作为
   预构建软件包处理。
2. 归档会与 recipe 中的固定值进行校验，存储路径由 recipe、宿主 ABI、嵌入
   rootfs、依赖存储和隔离设置共同决定。
3. 源码软件包在非特权账户下解包，并在上述容器中构建。预构建软件包跳过构建步骤。
4. 构建结果连同 manifest 和完成标记一起封存到包存储。接受存储前会检查 manifest
   的路径、模式、哈希和链接目标。
5. 激活会将 manifest 与活动文件系统比较，备份被接管的文件，写入指向存储的链接，
   并提交激活记录。运行中进程映射的文件会暂存并在关机时应用。
6. 状态数据库记录软件包、文件和新 generation。上一 generation 仍可用于
   `moirse rollback`。

`moirse --verify` 会将已激活文件与其记录的哈希、存储与其完成标记进行比较。
签名 manifest 会与受信密钥校验；设置 `security.require_signature = true` 后，
无法验证的软件包会被拒绝。`moirse rollback <id>` 可恢复 generation，无需重新
构建存储。上文机制说明概述了术语与恢复流程。

## 安装

官方安装程序是发布仓库中的 shell 脚本。它根据主机架构选择发布归档，下载归档及其 `.sha256`、`.sig` 文件，验证 Ed25519 签名和校验和，解包二进制并执行安装。以 root 运行：

```sh
curl -fsSL https://raw.githubusercontent.com/saves24/portalis/master/install.sh | sudo sh
```

安装指定版本时，将版本号作为参数传入：

```sh
curl -fsSL https://raw.githubusercontent.com/saves24/portalis/master/install.sh | sudo sh -s -- 0.1.0
```

安装程序将二进制安装到 `/usr/lib/portalis/portalis`，创建 `/usr/bin/moirse` 符号链接，创建运行时目录，并安装用于在关机时应用延迟激活的 `portalis.service` systemd 单元。若以本地二进制路径调用，安装程序接受该二进制；该路径不会下载或验证发布归档。

发布归档是名为
`portalis-<version>-<target>.tar.gz` 的 `.tar.gz` 文件。归档包含：

```text
portalis          静态二进制
install.sh        安装程序
LICENSE           MIT 许可证
release.pub       发布公钥
```

`install.sh` 中嵌入的公钥是下载路径的信任锚。归档内的 `release.pub` 可用于检查归档内部一致性，但不是独立的信任锚。如有需要，可以在解包前手动校验下载的归档。

安装程序支持 x86_64 和 aarch64 发布归档。其他架构必须从源码构建。官方发布二进制为静态链接，因此不依赖宿主 C 库；本地构建的二进制则使用本地工具链产生的链接方式。

### 安装程序与运行时依赖

下载发布归档的安装程序需要 `curl` 或 `wget`、`openssl`（Ed25519 验证需要版本 3）、`tar`、`gzip` 和 `sha256sum`。当软件包归档使用相应压缩格式时，管理器还会使用 `xz`、`zstd` 或 `bzip2`。`bubblewrap` 为可选依赖；不可用时，构建步骤使用前述 Landlock 回退路径。bubblewrap 与 Landlock 均不可用时，构建步骤仅以非特权账户运行，离线步骤会被拒绝。check 命令需要 `bubblewrap`；当 `check.required` 为 false 且 bubblewrap 不可用时，check 会跳过并输出警告。

若安装程序收到本地二进制，则不会下载发布归档；因此归档应在解包前完成校验。

### 从源码构建

源码树使用 `rust-toolchain.toml` 固定的 Rust 工具链：

```sh
cargo build --release --locked
```

该命令生成面向构建主机的本地二进制。仅当构建时同时提供 `PORTALIS_ROOTFS_IMAGE` 和 `image/manifest.toml`，才会嵌入 rootfs 镜像。官方发布二进制由项目的发布流程生成，与未配置的本地构建并不完全相同。

## 命令

| 命令 | 用途 |
| --- | --- |
| `moirse` | 列出已安装软件包 |
| `moirse install <archive>` | 从归档构建并应用软件包；无匹配 recipe 时导入 |
| `moirse remove <package>` | 解除软件包链接 |
| `moirse remove <package> --purge` | 解除链接并删除其存储目录 |
| `moirse remove <package> --pending` | 仅删除暂存副本，已安装版本保留 |
| `moirse remove <package> --force` | 覆盖依赖、文件占用或存储忙碌导致的拒绝 |
| `moirse rollback <id>` | 恢复 generation 中记录的软件包集合 |
| `moirse clean [--logs] [--store] [--backups] [--yes]` | 删除旧日志、无引用存储、过期构建树和被替代的备份 |
| `moirse --show <package>` | 显示单个软件包的版本、大小、依赖、被依赖关系和文件 |
| `moirse --file <path>` | 查询拥有指定路径的软件包 |
| `moirse --history` | 列出 generation 快照 |
| `moirse --verify` | 将每个已激活文件与其记录的哈希、每个存储与其完成标记进行比较 |
| `moirse --check` | 解析全部 recipe，并报告无效项 |
| `moirse --orphans` | 报告无引用存储、缺失存储和悬空链接 |
| `moirse --logs <package> [--tail N]` | 列出构建日志，或输出最新日志的最后 N 行 |
| `moirse --quiet` | 在长时间命令执行期间抑制进度行 |
| `moirse --discard-recovery` | 删除阻塞写命令的 activation 或 operation journal，并报告删除的路径 |
| `moirse --version` | 输出版本；存在嵌入 rootfs 时同时输出其标识 |

检查类选项 `--show`、`--file`、`--history`、`--orphans`、`--verify`、`--check` 和 `--logs` 不能与子命令组合。`--tail` 必须与 `--logs` 同时使用。写命令需要 root 权限。`clean` 会先报告计划，未指定 `--yes` 时不删除任何内容。

当另一个已安装软件包依赖目标软件包时，`remove` 会拒绝执行；`--force` 可覆盖该检查。若存储目录仍被运行中进程映射，`remove --purge` 也会拒绝删除；`--force` 可覆盖该检查。写命令会执行 housekeeping：删除一小时前的过期构建目录，并清理旧构建日志，无需另行调用 `clean`。

## Recipe

recipe 是纯文本文件，每行包含一个 `key = value` 语句。键为扁平或点分形式，`#` 开始注释，列表以逗号分隔，多行值写在 `<<MARKER` 行与结束 `MARKER` 行之间。

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

### Recipe 键

| 键 | 含义 |
| --- | --- |
| `package.name` | 软件包名；必填 |
| `package.version` | 软件包版本；必填 |
| `package.description` | 可读描述；不参与 recipe 哈希 |
| `package.hold` | 未指定 `--force` 时阻止删除 |
| `package.depends` | 以逗号分隔的软件包依赖 |
| `source.kind` | `source` 表示源码构建，`binary` 表示预构建软件包 |
| `source.file` | 归档文件名；必填 |
| `source.sha256` | 源码归档的 SHA-256；必填 |
| `source.dir` | 归档内目录；为空时自动检测 |
| `build.system` | `autotools`、`meson`、`cargo` 或 `custom`；默认为 `autotools` |
| `build.args` | 以逗号分隔的构建参数 |
| `build.cflags` | C 编译器参数 |
| `build.cxxflags` | C++ 编译器参数 |
| `build.rustflags` | Rust 编译器参数 |
| `build.isolation` | 设为 `rpath` 时，将依赖存储路径写入 ELF runpath |
| `build.env.<NAME>` | 构建步骤的附加环境变量 |
| `build.network` | 允许构建期间访问网络 |
| `build.writable` | 在构建沙箱中额外以读写方式挂载的宿主路径 |
| `build.read` | 在构建沙箱中额外以只读方式挂载的宿主路径 |
| `build.jobs` | 该 recipe 的并行构建任务数 |
| `build.patch` | 内联补丁块；按应用顺序重复 |
| `install.prefix` | 安装前缀；默认为 `/usr` |
| `install.setuid` | 允许保留 setuid 位的路径 |
| `install.setgid` | 允许保留 setgid 位的 `path:group` 条目 |
| `install.deps_ignore` | ELF 文件通过私有 rpath 解析库的相对路径前缀 |
| `files.preserve` | 首次复制后不再覆盖的配置文件路径 |
| `hooks.ldconfig` | 激活后运行 `ldconfig` |
| `hooks.icon_cache` | 刷新图标缓存的图标主题目录 |
| `hooks.daemon_reload` | 激活后运行 `systemctl daemon-reload` |
| `check.command` | 构建完成后、激活前运行的命令 |
| `check.timeout` | check 超时时间，单位为秒；默认为 300 |
| `check.required` | check 失败或无法执行时拒绝安装；默认为 `false` |

值会去除首尾空白。单引号或双引号可保留首尾空白、逗号和 `#` 字符；引号内的 `\n` 和 `\t` 会被识别。引号外的 `#` 开始注释。未知键会被拒绝；只有格式允许时键才可以重复，例如 `build.patch`。`moirse --check` 会验证 recipe 目录中的每个 recipe。

### 构建参数与补丁

`build.args` 由所选构建系统解释。对于 `autotools`，条目会追加到 `./configure`；对于 `meson`，条目会追加到 `meson setup`；对于 `cargo`，条目会传递给 cargo 调用；对于 `custom`，每个条目会在独立的 `sh -c` 中执行，并导出 `DESTDIR`、`PREFIX` 和 `SRCDIR`。条目以逗号分隔；包含逗号时可以加引号。因此，包含逗号的命令既可以直接加引号，也可以移入归档携带的脚本。

补丁以块为单位，按应用顺序重复该键。可选的 `optional = true` 字段用于跳过不再适用的补丁：

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

### 构建与 check 行为

`check.command` 在构建完成后、激活前运行，运行环境为嵌入的 rootfs，软件包及其依赖安装在一次性 root 中。check 不访问宿主文件系统，不访问网络，不具备 capability，并以 uid 65534 运行。非零退出码默认只产生警告；设置 `check.required = true` 后，失败或无法执行的 check 会拒绝安装。`check.timeout` 默认为 300 秒。未嵌入 rootfs 或缺少 bubblewrap 的构建会跳过 check；当 `check.required = true` 时，安装将被拒绝。

源码构建保留普通文件模式。setuid 和 setgid 位仅对 `install.setuid` 与 `install.setgid` 中声明的路径保留。setgid 条目必须指定组，该组在目标 root 的 `etc/group` 中解析；未指定组或组不存在的条目会拒绝安装。

预构建软件包声明 `source.kind = binary`，并且没有构建步骤。无匹配 recipe 的归档会作为预构建软件包导入：软件包名和版本从文件名读取，或从 `.deb` 的控制字段读取。若归档被单一顶层目录包裹，则会被拒绝；归档根目录必须对应文件系统根目录。

导入归档保留普通文件模式。导入归档中的 setuid 或 setgid 位默认会被拒绝，除非安装时设置 `PORTALIS_KEEP_PRIVILEGED=1`；设置该覆盖后，这些位会以 `install.setuid` 或 `install.setgid` 记录到派生的 recipe 中。setgid 条目记录文件头中指定的组；安装时会在目标 root 中解析该组，组不存在时拒绝该软件包。

构建步骤可以访问源码树、只读工具链视图以及软件包元数据明确提供的依赖存储。依赖的 include、library、pkg-config、CMake 和 rpath 路径会根据这些存储加入；需要额外头文件或库的构建，必须声明相应依赖或提供自身副本。

## 配置

可选配置文件为 `/etc/portalis/config.port`。缺少的键保留默认值。

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

| 键 | 默认值 | 含义 |
| --- | --- | --- |
| `security.require_signature` | `false` | 拒绝无法使用受信密钥验证的 manifest；仅表示本机受信，不代表上游来源 |
| `maintenance.retain_generations` | `5` | 回收回滚数据前保留的 generation 数量 |
| `maintenance.backup_retention_days` | `30` | 被替代备份可被删除的保留天数 |
| `build.scrub_paths` | `true` | 重写暂存文件中的构建主机路径 |
| `build.jobs` | 未设置 | 并行构建任务数；未设置时为可用核心数的一半 |
| `build.limit_memory_mb` | 未设置 | 地址空间上限，单位为 MiB；未设置时为宿主内存的一半 |
| `build.limit_file_mb` | 未设置 | 单文件大小上限，单位为 MiB；未设置时为工作区可用空间的一半 |
| `build.limit_cpu_seconds` | 未设置 | CPU 时间上限；未设置时不限制 CPU 时间 |
| `build.limit_open_files` | 未设置 | 打开文件数上限；未设置时为硬限制的一半 |
| `rootfs.cache` | `runtime` | `runtime` 或 `tmpfs` 使用 `/run`；`persistent` 使用 `/var/lib/portalis/rootfs` |

值为 `0` 会移除相应的资源上限。`build.jobs = 0` 选择默认工作线程数。每个构建步骤有独立的 3600 秒超时，除非 `PORTALIS_BUILD_TIMEOUT` 指定其他正值。配置格式错误会中止安装，而不会静默放宽要求。

隔离机制按以下顺序选择：bubblewrap、Landlock，最后是仅以非特权账户运行。`PORTALIS_NO_BWRAP=1` 只跳过 bubblewrap；Landlock 在可用时仍会启用。在 Landlock 路径上，seccomp 过滤器会为离线步骤阻断 INET 和 INET6 套接字。没有开关可以移除已选择的机制。当 bubblewrap 和 Landlock 均不可用时，由于进程无法保证阻断套接字，离线步骤会被拒绝。

构建哈希包含当前隔离机制、宿主 ABI 指纹、嵌入的 rootfs 摘要和依赖存储路径。因此，当这些输入不同时，同一 recipe 会解析到不同的存储路径。构建步骤会忽略 `PORTALIS_WIDE_READ` 设置。

## 目录布局

| 路径 | 内容 |
| --- | --- |
| `/usr/portalis/packages/` | 软件包存储 |
| `/usr/portalis/etc/` | 每个软件包对外暴露的 `etc` 树 |
| `/usr/portalis/appconfig/` | 每个软件包的机器本地构建参数 |
| `/etc/portalis/packages/*.port` | Recipe |
| `/etc/portalis/config.port` | 安全、维护和构建选项 |
| `/etc/portalis/signing.key` | 本地签名密钥（存在时） |
| `/etc/portalis/trusted-keys/` | 受信公钥 |
| `/var/db/portalis/db.sqlite` | 软件包、文件和 generation 数据库 |
| `/var/lib/portalis/` | 状态锁、激活记录、待处理事务、备份和 `last-good.json` |
| `/var/lib/portalis/backup/` | 事务替换宿主文件时生成的备份 |
| `/var/lib/portalis/rootfs/` | `rootfs.cache = persistent` 时的持久 rootfs 缓存 |
| `/run/portalis/rootfs/` | `rootfs.cache = runtime` 或 `tmpfs` 时的运行时 rootfs 缓存 |
| `/var/log/portalis/builds/` | 构建日志 |
| `/etc/systemd/system/shutdown.target.wants/portalis.service` | 在关机时应用暂存激活的单元 |

存储路径包含 recipe 和构建运行环境。不同的隔离模式、宿主 ABI、rootfs 镜像、依赖集合或 scrub 设置会产生不同的目录。

## 运维说明

- 写命令会修改系统路径，必须以 root 运行。可先执行
  `PORTALIS_DRY_RUN=1 moirse install <archive>`，在写入前查看事务将替换的文件。
- 激活前会检查每个 manifest 路径。未声明的 setuid 或 setgid 位，以及指向 `/home`、`/root`、`/proc`、`/sys` 或 `/dev` 等受保护宿主位置的链接，会被拒绝。
- 仅当 manifest 与 recipe 和归档一致时，软件包才会被接受。未配置受信密钥时，未签名构建会带警告接受；安装受信密钥后，应设置 `security.require_signature = true`。
- 签名密钥必须由 root 持有，且仅所有者可读（`chmod 600`）；否则签名操作会被拒绝。
- `security.require_signature` 会使用受信密钥校验 manifest。签名密钥位于本机：在本机签名的软件包只能说明本机处理过它，不能证明上游来源。对不可信来源的软件包，应使用独立签名或独立校验渠道。
- 运行中进程映射的文件不会被原地替换。事务会暂存并在关机时应用，无参数的 `moirse` 会报告待处理软件包。文件是否正在使用从 `/proc` 读取；无法读取该信息时，事务会暂存到关机时处理。
- 对活动系统进行更改后，应运行 `moirse --verify`。它会报告被修改的存储文件、软件包记录缺失的条目以及未完成的激活；发现问题时以非零状态退出。
- `rollback` 恢复 generation，但保留存储目录，因此回滚不需要重新构建。`moirse clean --store` 回收没有软件包或保留 generation 引用的存储。
- 无 recipe 导入的归档会记录其所安装 payload 的 SHA-256。对于 `.deb`，该值是 payload 成员，而不是外层归档。该哈希用于标识文件，不用于认证文件。`security.require_signature` 只校验本机受信密钥，不能证明软件包来自外部上游。
- 导入归档若包含 setuid 或 setgid 文件，默认会被拒绝，除非设置 `PORTALIS_KEEP_PRIVILEGED=1`。setgid 条目记录文件头指定的组；安装时会在目标 root 中解析该组，组不存在时拒绝该软件包。
- `--discard-recovery` 会删除阻塞写命令的 activation 或 operation journal，并报告删除的每个路径。该选项适用于已检查 journal 并决定丢弃的操作人员；正常恢复应允许完成。

## 许可证

Portalis 源码采用 MIT 许可证。发布资源还包含以 GPL-2.0 授权的 BusyBox；参见
`THIRD_PARTY_NOTICES.md` 和 `LICENSES/GPL-2.0`。
