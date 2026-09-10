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
 *   The BIOS verify (pw module fn 0x3314, platform type 3) does:
 *       win[0]=0x21 win[2]=1(sub) win[3]=3(type)  -> doorbell
 *       write X (16 bytes, stored config value)
 *       write family u16 (e.g. 0xCF1B)
 *       read  R (32 bytes)
 *       pass  iff R[0:16] == X          (R is then zeroed — Dell hides it)
 *   This tool performs the same session with an X of your choosing and
 *   SHOWS the response instead of zeroing it. If R is input-independent,
 *   R[0:16] is the machine's expected value for that family.
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

int main(int argc, char **argv)
{
    unsigned family = 0xCF1B, sub = 1, type = 3;
    int full = 0, i;
    unsigned char x[16] = {0}, xr[16], r_zero[32], r_rand[32];

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--full")) full = 1;
        else if (!strcmp(argv[i], "--family") && i+1 < argc)
            family = (unsigned)strtoul(argv[++i], NULL, 16);
        else if (!strcmp(argv[i], "--sub") && i+1 < argc)
            sub = (unsigned)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--type") && i+1 < argc)
            type = (unsigned)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--x") && i+1 < argc) {
            const char *h = argv[++i];
            for (int k = 0; k < 16 && h[2*k] && h[2*k+1]; k++) {
                char b[3] = { h[2*k], h[2*k+1], 0 };
                x[k] = (unsigned char)strtoul(b, NULL, 16);
            }
        } else {
            fprintf(stderr, "usage: %s [--full] [--family XXXX] [--sub 0|1|2] "
                            "[--type 0..6] [--x 32hex]\n", argv[0]);
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
    puts("Read-only subs only (0/1/2). Bare metal, root. REPORT.md §10–11.\n");

    if (!full) {
        printf("family=0x%04X sub=%u type=%u\n", family, sub, type);
        for (int k = 0; k < 16; k++) xr[k] = (unsigned char)(rand() & 0xFF);
        int n1 = session(sub, type, x, 16, family, type == 3, r_zero);
        if (n1 < 0) { printf("no response (%d). Try --type 0..2, or --full.\n", n1); return 1; }
        int n2 = session(sub, type, xr, 16, family, type == 3, r_rand);
        dump("R (X=00..00)", r_zero, n1);
        if (n2 > 0) dump("R (X=random)", r_rand, n2);
        if (n2 > 0 && !memcmp(r_zero, r_rand, 16) && memcmp(r_zero, x, 16)) {
            puts(">>> INPUT-INDEPENDENT RESPONSE: R[0:16] is this machine's");
            puts(">>> expected value for this family. Render it:");
            puts(">>>   python3 bios-analysis/dell_keygen.py --interpret8fc8 <hex>");
        } else if (n2 > 0 && !memcmp(r_rand, xr, 16)) {
            puts(">>> ECHO mode: EC validates only (no leak via this sub).");
            puts(">>> Try --sub 0 / --sub 2 / other --type, then physical routes.");
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
