# sshfm

A small SSH file manager + text editor written in C++, with an
[libssh](https://www.libssh.org/)-based server.  Connect with plain
`ssh -p 2222 anyuser@host` (any password is accepted) and you land in a TUI
that is sandboxed to one directory: browse / create / delete / move / edit
files, with multi-user presence counters, directory-wide and global bells,
editor locks, broadcast messages and an optional login captcha.

This directory is a **self-contained buildable release**: it bundles the
sshfm source, the sources of every dependency, and a one-shot build script.
Nothing needs to be installed system-wide (no system libssh / OpenSSL / zlib).

## Layout

```
sshfm/
├─ build.sh          # one-shot build (Linux / WSL)
├─ build.ps1         # Windows wrapper that drives WSL
├─ src/
│  ├─ sshfm.cpp      # the whole implementation (single file)
│  └─ colltab.inc    # embedded collation table (name sorting, pre-generated)
├─ deps/             # dependency sources
│  ├─ zlib-1.3.1.tar.gz
│  ├─ openssl-3.0.13.tar.gz
│  └─ libssh-0.12.2.tar.xz
└─ out/              # build output (created by build.sh)
   └─ sshfm          # statically linked Linux x86-64 executable
```

## Build requirements (on the build machine)

- Linux or WSL
- `g++` (C++17), `cmake` (>= 3.10), `make`, `perl`, `tar`, `xz`

There are **no runtime** dependencies: the result is a statically linked ELF.

## Building

Linux / WSL:

```bash
./build.sh              # first run builds zlib -> OpenSSL -> libssh -> sshfm
./build.sh --clean      # wipe the cache and rebuild everything
./build.sh --jobs 8     # choose the number of parallel jobs
```

Windows (PowerShell, via WSL):

```powershell
.\build.ps1
.\build.ps1 --clean
```

The build:

1. **zlib 1.3.1** → `libz.a`
2. **OpenSSL 3.0.13** → `libcrypto.a` (`no-shared`)
3. **libssh 0.12.2** → `libssh.a` (static, server support enabled, linked
   against the OpenSSL and zlib built above)
4. **sshfm** → statically linked against all three, written to `out/sshfm`

Dependencies are compiled into a cache directory (default
`${TMPDIR:-/tmp}/sshfm-build`); repeated builds skip finished steps.
Override with environment variables:

```bash
SSHFM_WORK=/path/to/cache JOBS=8 ./build.sh
```

## Running

```bash
./out/sshfm -dir ./data -port 2222
```

then:

```bash
ssh -p 2222 anyone@127.0.0.1     # any password works
```

Command line options:

| Option | Description |
| --- | --- |
| `-dir D` | sandbox root directory (default `./data`) |
| `-port N` | SSH listen port (default `2222`) |
| `-time +H` | timezone offset in hours for displayed times, e.g. `-time +8`, `-time -5` (default `+0`) |
| `-captcha [S]` | require a captcha before the TUI, `S` = countdown seconds (default 30) |
| `-captcha [S]L` | weak captcha: just type the 8 digits shown on screen |
| `-auth N` | authentication phase timeout in seconds (default 60) |
| `--help` | show help and exit |

## Notes

- The host key is generated on first run as `sshfm_hostkey` next to the
  executable.
- Inside the sandbox every entry's real file name carries a `1` prefix, and
  its metadata (creator/editor IP, timestamps, stable id) lives in a sidecar
  file with a `0` prefix.
- Text rendering is grapheme-cluster aware (combining marks, emoji ZWJ
  sequences, flags, skin-tone modifiers, ...).  At login the client is probed
  for how it renders VS16 / ZWJ so widths can be calibrated.
