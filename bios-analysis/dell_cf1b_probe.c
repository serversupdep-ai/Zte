/*
 * dell_cf1b_probe.c — Dell CF1B (and 1B58/9ABE/3FE2/8FC8) BIOS-password
 * challenge probe for OptiPlex 3090-class machines on current firmware.
 *
 * WHY THIS TOOL EXISTS (bios-analysis/REPORT.md §11):
 *   On BIOS 2.27.0 the password module's family membership list is
 *   [1B58, 9ABE, 3FE2, CF1B, 8FC8] — all of these route password
 *   verification to the EC/SMM security service via mailbox command 0x21.
 *   The legacy local algorithms (BF97 fallback etc.) are NOT consulted for
 *   these families on current firmware, so legacy keygens cannot work.
 *   The expected value is computed inside the EC with per-machine secrets
 *   and never appears in the BIOS image.
 *
 *   The BIOS verify (pw module fn 0x3314, platform type 3 — REPORT §13,
 *   fully reversed from the dumps) does:
 *       X  = SHA256(candidate[0..16] || salt)        (salt 8dfc7b25, 2.27.0)
 *       win[0]=0x21 win[2]=1(sub) win[3]=3(type)  -> doorbell
 *       xfer_write(X, 32); xfer_write(family u16)
 *       R  = xfer_read(32)
 *       pass iff R == SHA256(X || salt)
 *   i.e. the EC holds X_enrolled = SHA256(true_password || salt) and returns
 *   the confirmation hash only when the sent X matches it.
 *
 *   => --password <P> turns this tool into a definitive password VALIDATOR:
 *      it computes X itself (built-in SHA-256 + salt) and checks R. Loop it
 *      over candidates from Linux — no setup screen, no brick risk.
 *      (2.0.7/8FC8 machines: salt is "0001" — see --salt.)
 *
 * Mailbox transport (REPORT.md §10.3): port 0x910 = index, 0x911 = data;
 * selector 0x00 = command doorbell (poll until 0), selectors 0x10..0x2F =
 * 32-byte message window; command 0x17 = packetized data transfer
 * (8 bytes per packet, win[3]=len, win[2]=1 go / poll bit0).
 *
 * Sub-commands of 0x21 seen in firmware: 0 (capability query), 1 (verify),
 * 2 (secondary check), 3 (password change/enroll — DESTRUCTIVE, deliberately
 * NOT implemented here).
 *
 * Build:  gcc -O2 -o dell_cf1b_probe dell_cf1b_probe.c
 * Run:    sudo ./dell_cf1b_probe                  # CF1B campaign (type 3)
 *         sudo ./dell_cf1b_probe --full           # all families x subs x types
 *         sudo ./dell_cf1b_probe --family 1B58 --sub 1 --type 3 --x <hex32>
 *
 * Run on BARE METAL as root (a VM usually traps/forwards port 0x910 and the
 * EC is not behind it). For recovery of machines you own or are authorized
 * to service. If the probe reports ECHO mode (pure verifier), the remaining
 * routes are physical: SPI dump + patch (REPORT.md §8) or EC firmware
 * analysis on a decrypted dump.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#if defined(__linux__)
#include <sys/io.h>
static inline void outportb(unsigned short p, unsigned char v){ __asm__ volatile("outb %0,%1"::"a"(v),"Nd"(p)); }
static inline unsigned char inportb(unsigned short p){ unsigned char r; __asm__ volatile("inb %1,%0":"=a"(r):"Nd"(p)); return r; }
#define IO_INIT() (iopl(3) == 0)
#else
#error "Linux only (FreeDOS: adapt outportb/inportb + drop iopl)"
#endif

#define PORT_IDX 0x910
#define PORT_DAT 0x911
#define WIN_BASE 0x10
#define SEL_CMD  0x00
#define TIMEOUT  2000000

static void win_write(unsigned i, unsigned char v){ outportb(PORT_IDX, (unsigned char)(WIN_BASE+i)); outportb(PORT_DAT, v); }
static unsigned char win_read(unsigned i){ outportb(PORT_IDX, (unsigned char)(WIN_BASE+i)); return inportb(PORT_DAT); }

static int wait_ack(void)
{
    for (long t = 0; t < TIMEOUT; t++) {
        outportb(PORT_IDX, SEL_CMD);
        if (inportb(PORT_DAT) == 0) return 0;
    }
    return -1;
}

static int doorbell(unsigned char cmd)
{
    outportb(PORT_IDX, SEL_CMD); outportb(PORT_DAT, cmd);
    return wait_ack();
}

static int xfer_write(const unsigned char *data, int len)
{
    int off = 0;
    win_write(3, 0); win_write(2, 0);
    if (doorbell(0x17) != 0) return -1;
    while (off < len) {
        int n = len - off > 8 ? 8 : len - off;
        for (int i = 0; i < n; i++) win_write(4 + i, data[off + i]);
        win_write(3, (unsigned char)n); win_write(2, 1);
        if (wait_ack() != 0) return -1;
        for (long t = 0; t < TIMEOUT; t++)
            if ((win_read(2) & 1) == 0) goto consumed;
        return -1;
consumed:   off += n;
    }
    win_write(3, 0); win_write(2, 1);          /* end-of-transfer */
    return wait_ack();
}

static int xfer_read(unsigned char *out, int len)
{
    int got = 0;
    win_write(3, 0); win_write(2, 0);
    if (doorbell(0x17) != 0) return -1;
    while (got < len) {
        unsigned char cnt = 0;
        for (long t = 0; t < TIMEOUT; t++)
            if (win_read(2) & 1) { cnt = win_read(3); break; }
        if (!cnt) break;
        if (cnt > 8) cnt = 8;
        if (cnt > len - got) cnt = (unsigned char)(len - got);
        for (int i = 0; i < cnt; i++) out[got + i] = win_read(4 + i);
        got += cnt;
        win_write(3, 0); win_write(2, 0);      /* consumed */
    }
    return got;
}

/* one 0x21 session: sub, type, optional 16-byte X, optional family u16 */
static int session(unsigned sub, unsigned type,
                   const unsigned char *x16, unsigned xlen,
                   unsigned family, int send_family,
                   unsigned char resp[32])
{
    win_write(2, (unsigned char)sub);
    win_write(3, (unsigned char)type);
    if (doorbell(0x21) != 0) return -1;
    if (xlen && xfer_write(x16, (int)xlen) != 0) return -2;
    if (send_family) {
        unsigned char fam[2] = { (unsigned char)(family & 0xFF),
                                 (unsigned char)(family >> 8) };
        if (xfer_write(fam, 2) != 0) return -3;
    }
    return xfer_read(resp, 32);
}

static void dump(const char *label, const unsigned char *b, int n)
{
    printf("%-22s ", label);
    for (int i = 0; i < n; i++) printf("%02x", b[i]);
    printf("  |");
    for (int i = 0; i < n; i++)
        putchar(b[i] >= 0x20 && b[i] < 0x7f ? b[i] : '.');
    printf("|\n");
}

/* ---- compact SHA-256 (for --password mode; REPORT §13) ------------------ */
typedef struct { uint32_t h[8]; uint64_t len; unsigned char buf[64]; size_t n; } sha256_ctx;

static const uint32_t sha_k[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))
static void sha_block(sha256_ctx *c, const unsigned char *p)
{
    uint32_t w[64], a,b,d,e,f,g,hh,cc,t1,t2; int i;
    for (i=0;i<16;i++) w[i]=(p[4*i]<<24)|(p[4*i+1]<<16)|(p[4*i+2]<<8)|p[4*i+3];
    for (;i<64;i++){uint32_t s0=ROR(w[i-15],7)^ROR(w[i-15],18)^(w[i-15]>>3),
                    s1=ROR(w[i-2],17)^ROR(w[i-2],19)^(w[i-2]>>10);
                    w[i]=w[i-16]+s0+w[i-7]+s1;}
    a=c->h[0];b=c->h[1];cc=c->h[2];d=c->h[3];e=c->h[4];f=c->h[5];g=c->h[6];hh=c->h[7];
    for (i=0;i<64;i++){
        uint32_t S1=ROR(e,6)^ROR(e,11)^ROR(e,25), ch=(e&f)^((~e)&g);
        t1=hh+S1+ch+sha_k[i]+w[i];
        uint32_t S0=ROR(a,2)^ROR(a,13)^ROR(a,22), maj=(a&b)^(a&cc)^(b&cc);
        t2=S0+maj;
        hh=g;g=f;f=e;e=d+t1;d=cc;cc=b;b=a;a=t1+t2;
    }
    c->h[0]+=a;c->h[1]+=b;c->h[2]+=cc;c->h[3]+=d;c->h[4]+=e;c->h[5]+=f;c->h[6]+=g;c->h[7]+=hh;
}
static void sha256_init(sha256_ctx *c){c->h[0]=0x6a09e667;c->h[1]=0xbb67ae85;c->h[2]=0x3c6ef372;c->h[3]=0xa54ff53a;c->h[4]=0x510e527f;c->h[5]=0x9b05688c;c->h[6]=0x1f83d9ab;c->h[7]=0x5be0cd19;c->len=0;c->n=0;}
static void sha256_update(sha256_ctx *c, const unsigned char *p, size_t n){
    c->len+=n;
    while(n){ size_t k=64-c->n; if(k>n)k=n; memcpy(c->buf+c->n,p,k); c->n+=k; p+=k; n-=k;
        if(c->n==64){sha_block(c,c->buf);c->n=0;} }
}
static void sha256_final(sha256_ctx *c, unsigned char out[32]){
    uint64_t bits=c->len*8; unsigned char pad=0x80; int i;
    sha256_update(c,&pad,1);
    unsigned char z=0; while(c->n!=56) sha256_update(c,&z,1);
    unsigned char l[8]; for(i=0;i<8;i++) l[i]=(unsigned char)(bits>>(56-8*i));
    sha256_update(c,l,8);
    for(i=0;i<8;i++){out[4*i]=c->h[i]>>24;out[4*i+1]=c->h[i]>>16;out[4*i+2]=c->h[i]>>8;out[4*i+3]=c->h[i];}
}
/* the challenge primitive: SHA256(data || salt) — REPORT §13, fn 0x1bb4 */
static void challenge_hash(const unsigned char *data, size_t n,
                           const unsigned char salt[4], unsigned char out[32])
{
    sha256_ctx c; sha256_init(&c);
    sha256_update(&c, data, n);
    sha256_update(&c, salt, 4);
    sha256_final(&c, out);
}

int main(int argc, char **argv)
{
    unsigned family = 0xCF1B, sub = 1, type = 3;
    int full = 0, i, pwlen = 16;
    unsigned char x[32] = {0}, xr[32], r_zero[32], r_rand[32];
    unsigned char salt[4] = { 0x8d, 0xfc, 0x7b, 0x25 };   /* 2.27.0 (REPORT §13) */
    const char *password = NULL;
    int xlen = 16;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--full")) full = 1;
        else if (!strcmp(argv[i], "--family") && i+1 < argc)
            family = (unsigned)strtoul(argv[++i], NULL, 16);
        else if (!strcmp(argv[i], "--sub") && i+1 < argc)
            sub = (unsigned)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--type") && i+1 < argc)
            type = (unsigned)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--password") && i+1 < argc)
            password = argv[++i];
        else if (!strcmp(argv[i], "--pwlen") && i+1 < argc)
            pwlen = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--salt") && i+1 < argc) {
            const char *h = argv[++i];
            for (int k = 0; k < 4 && h[2*k] && h[2*k+1]; k++) {
                char b[3] = { h[2*k], h[2*k+1], 0 };
                salt[k] = (unsigned char)strtoul(b, NULL, 16);
            }
        }
        else if (!strcmp(argv[i], "--x") && i+1 < argc) {
            const char *h = argv[++i];
            for (int k = 0; k < 32 && h[2*k] && h[2*k+1]; k++) {
                char b[3] = { h[2*k], h[2*k+1], 0 };
                x[k] = (unsigned char)strtoul(b, NULL, 16);
            }
            xlen = 32;
        } else {
            fprintf(stderr, "usage: %s [--password <P>] [--pwlen N] [--salt 8hex]\n"
                            "              [--full] [--family XXXX] [--sub 0|1|2] "
                            "[--type 0..6] [--x 64hex]\n"
                            "  --password P : validate candidate P (computes X=SHA256(P16||salt),\n"
                            "                 checks R == SHA256(X||salt))  [REPORT §13]\n"
                            "  --salt       : default 8dfc7b25 (2.27.0); use 30303031 (\"0001\") on 2.0.7\n", argv[0]);
            return 1;
        }
    }
    if (sub > 2) {
        fprintf(stderr, "sub=3 (enroll) is destructive and not implemented. "
                        "Refusing.\n");
        return 1;
    }
    if (!IO_INIT()) { perror("iopl"); return 1; }

    puts("Dell CF1B/family challenge probe — mailbox 0x910/0x911, cmd 0x21");
    puts("Read-only subs only (0/1/2). Bare metal, root. REPORT.md §10-11, §13.\n");

    if (password) {
        unsigned char p16[16] = {0}, X[32], expect[32], R[32];
        int n = (int)strlen(password); if (n > pwlen) n = pwlen;
        memcpy(p16, password, n);
        challenge_hash(p16, 16, salt, X);
        challenge_hash(X, 32, salt, expect);
        printf("password candidate: \"%s\" (padded to %d)\n", password, pwlen);
        dump("X = SHA256(P||salt)", X, 32);
        int nr = session(sub, type, X, 32, family, type == 3, R);
        if (nr < 0) { printf("no response (%d)\n", nr); return 1; }
        dump("R (EC response)", R, nr);
        dump("expected R", expect, 32);
        if (nr >= 32 && !memcmp(R, expect, 32)) {
            puts(">>> PASSWORD CONFIRMED: R == SHA256(X||salt). This is the password.");
        } else {
            puts(">>> not this password (R != SHA256(X||salt)).");
        }
        return 0;
    }

    if (!full) {
        printf("family=0x%04X sub=%u type=%u\n", family, sub, type);
        for (int k = 0; k < 32; k++) xr[k] = (unsigned char)(rand() & 0xFF);
        int n1 = session(sub, type, x, xlen, family, type == 3, r_zero);
        if (n1 < 0) { printf("no response (%d). Try --type 0..2, or --full.\n", n1); return 1; }
        int n2 = session(sub, type, xr, 32, family, type == 3, r_rand);
        dump("R (X=00..00)", r_zero, n1);
        if (n2 > 0) dump("R (X=random)", r_rand, n2);
        if (n2 > 0 && !memcmp(r_zero, r_rand, 32)) {
            puts(">>> INPUT-INDEPENDENT R — likely error/status. See REPORT §13.");
        } else if (n2 > 0 && !memcmp(r_rand, xr, 32)) {
            puts(">>> ECHO mode: EC validates only (no leak via this sub).");
            puts(">>> Use --password <P> to validate candidates (REPORT §13).");
        } else if (n2 > 0) {
            puts(">>> R varies with X — challenge transform present.");
            puts(">>> Validate candidates: --password <P>  (REPORT §13)");
        }
        return 0;
    }

    /* full matrix: families x sub 1 (types 0..3) + sub 0/2 (types 0..2,4,5) */
    unsigned fams[] = { 0xCF1B, 0x1B58, 0x9ABE, 0x3FE2, 0x8FC8 };
    const char *fn[] = { "CF1B", "1B58", "9ABE", "3FE2", "8FC8" };
    for (unsigned f = 0; f < sizeof(fams)/sizeof(fams[0]); f++) {
        printf("\n===== family %s (0x%04X) =====\n", fn[f], fams[f]);
        for (unsigned t = 0; t <= 3; t++) {
            int n = session(1, t, x, 16, fams[f], t == 3, r_zero);
            if (n > 0) { printf("sub=1 type=%u:\n", t); dump("  R", r_zero, n); }
        }
        for (unsigned t = 0; t <= 5; t++) {
            if (t == 3) continue;               /* sub 0/2 exclude type 3 */
            int n = session(0, t, x, 16, fams[f], 0, r_zero);
            if (n > 0) { printf("sub=0 type=%u:\n", t); dump("  R", r_zero, n); }
            n = session(2, t, x, 16, fams[f], 0, r_zero);
            if (n > 0) { printf("sub=2 type=%u:\n", t); dump("  R", r_zero, n); }
        }
    }
    puts("\nFeed any interesting 32-byte R to:");
    puts("  python3 bios-analysis/dell_keygen.py --interpret8fc8 <hex>");
    return 0;
}
