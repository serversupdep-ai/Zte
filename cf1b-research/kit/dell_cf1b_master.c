/*
 * dell_cf1b_master.c — Dell BIOS master-code reader for the EC-era suffix
 * families (CF1B, 1B58, 9ABE, 3FE2, 8FC8) on OptiPlex 3090-class machines.
 *
 * THIS IS THE MACHINE-SPECIFIC SOLUTION (CF1B_FINDINGS.md §11).
 *
 * Everything below was reversed from the user machine's own firmware
 * (OptiPlex 3090, System BIOS 2.27.0, vault module + DellEcIo provider)
 * and validated end-to-end by CPU emulation of the SMM code path
 * (Unicorn, fn 0x37AC type-6 session — rv=EFI_SUCCESS, output verified
 * byte-exact for all three response-map branches). No legacy-suffix
 * algorithm and no lookup table is used anywhere.
 *
 * PROVEN PROTOCOL (CF1B_FINDINGS.md §11):
 *   EC mailbox (DellEcIo, ports 0x910/0x911 — verified in the 3090's own
 *   DellEcIo provider module, selector table 0x10..0x1F identity):
 *     1. session open : win[2]=3 (sub), win[3]=6 (type 6 = GENERATE),
 *                       doorbell 0x21          — SMM fn 0x37AC
 *     2. send         : the SERVICE TAG bytes (e.g. "H2FS5S3", 7 bytes)
 *     3. send         : 1 byte = suffix LSB (0x1B for CF1B; the EC list
 *                       families 1B58/9ABE/3FE2/CF1B/8FC8 have distinct LSBs)
 *     4. recv         : 32 bytes  -> the EC-computed codes
 *     5. recv         : 1 status byte (0x00 = success; fn 0x31B4 map)
 *   Response -> master code (SMM fn 0x8E18, all three branches emulated):
 *     CF1B (not in local dispatch table, fn 0x8060 -> 0xFFFF):
 *         master = resp[0..15] VERBATIM — the EC returns the fully-formed
 *         16-character code; resp[16..31] is printed as a second candidate
 *         (challenge "code 2" half).
 *     8FC8 (dispatch index 0, alphabet @VA 0xa280 of the 2.27.0 module):
 *         master[i] = alphabet[(resp[i] + resp[i+16]) % 72]
 *     E7A8-family is NOT EC-routed (legacy local list) — out of scope here.
 *
 * The EC itself computes the code from (service tag, family byte) with
 * per-machine secrets — that is why no offline keygen can exist for CF1B
 * (CF1B_FINDINGS.md §10) and why this tool asks the machine's own EC.
 *
 * Session sub 3 / type 6 is the SMM's own GENERATE request: it sends the
 * tag + family byte and only RECEIVES. Types 4/5 (enroll/write, which send
 * the fixed command 8449624d...) are NOT implemented — deliberately.
 *
 * Transport (identical to dell_cf1b_probe.c, cross-checked against the
 * 3090 DellEcIo provider disassembly):
 *   port 0x910 = selector/index, port 0x911 = data;
 *   selector 0x00 = command doorbell (poll until 0);
 *   selectors 0x10..0x1F = 16-byte message window;
 *   command 0x17 = packetized transfer (<=8 bytes per packet,
 *   win[3]=count, win[2]=1 go / poll bit0).
 *
 * Build:  gcc -O2 -o dell_cf1b_master dell_cf1b_master.c
 * Run:    sudo ./dell_cf1b_master                       # tag H2FS5S3, CF1B
 *         sudo ./dell_cf1b_master -t XXXXXXX -f CF1B
 *         sudo ./dell_cf1b_master -f 8FC8               # alphabet-mapped
 *
 * BARE METAL as root (VMs trap/forward port I/O; the EC is not behind
 * them). For machines you own or are authorized to service.
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
#error "Linux only"
#endif

static unsigned PORT_IDX = 0x910;
static unsigned PORT_DAT = 0x911;
#define WIN_BASE 0x10
#define SEL_CMD  0x00
#define TIMEOUT  2000000

/* EC-path alphabet of the 3090 2.27.0 vault module (@VA 0xa280), used by
 * the 8FC8-branch of fn 0x8E18 (dispatch index 0). CF1B does NOT use it. */
static const char ALPHABET_EC[] =
    "0Q2drGk99WLJ1EGnqR5y3DGr16hN4seZPRM2zz2pzcU7JaBXIjbkGZrkQFMxN[Z638myIL2r";

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

/*
 * The GENERATE session (SMM fn 0x37AC, type-6 branch — §11):
 *   win[2]=3, win[3]=6, doorbell 0x21;
 *   xfer_write(tag, taglen);
 *   xfer_write(&suffix_lsb, 1);
 *   xfer_read(resp, 32);
 *   xfer_read(&status, 1);            (best-effort)
 */
static int session_generate(const char *tag, unsigned suffix,
                            unsigned char resp[32], int *status)
{
    unsigned char lsb = (unsigned char)(suffix & 0xFF);
    unsigned char st = 0xFF;
    size_t n = strlen(tag);
    if (n == 0 || n > 32) return -100;

    win_write(2, 3);                            /* sub  = 3        */
    win_write(3, 6);                            /* type = 6 GENERATE */
    if (doorbell(0x21) != 0) return -1;
    if (xfer_write((const unsigned char *)tag, (int)n) != 0) return -2;
    if (xfer_write(&lsb, 1) != 0) return -3;
    int got = xfer_read(resp, 32);
    if (got < 0) return -4;
    int s = xfer_read(&st, 1);                  /* status byte (fn 0x31B4: 0 = ok) */
    if (status) *status = (s == 1) ? st : 0xFE; /* 0xFE = not delivered */
    return got;
}

static void dump(const char *label, const unsigned char *b, int n)
{
    printf("%-26s ", label);
    for (int i = 0; i < n; i++) printf("%02x", b[i]);
    printf("  |");
    for (int i = 0; i < n; i++)
        putchar(b[i] >= 0x20 && b[i] < 0x7f ? b[i] : '.');
    printf("|\n");
}

int main(int argc, char **argv)
{
    const char *tag = "H2FS5S3";
    unsigned family = 0xCF1B;

    for (int i = 1; i < argc; i++) {
        if ((!strcmp(argv[i], "-t") || !strcmp(argv[i], "--tag")) && i+1 < argc)
            { tag = argv[++i]; }
        else if ((!strcmp(argv[i], "-f") || !strcmp(argv[i], "--family")) && i+1 < argc) {
            const char *s = argv[++i];
            if (!strcmp(s, "CF1B")) family = 0xCF1B;
            else if (!strcmp(s, "1B58")) family = 0x1B58;
            else if (!strcmp(s, "9ABE")) family = 0x9ABE;
            else if (!strcmp(s, "3FE2")) family = 0x3FE2;
            else if (!strcmp(s, "8FC8")) family = 0x8FC8;
            else family = (unsigned)strtoul(s, NULL, 16);
        }
        else if (!strcmp(argv[i], "--port") && i+2 < argc) {
            PORT_IDX = (unsigned)strtoul(argv[++i], NULL, 0);
            PORT_DAT = (unsigned)strtoul(argv[++i], NULL, 0);
        } else {
            fprintf(stderr,
"usage: sudo %s [-t SERVICETAG] [-f CF1B|1B58|9ABE|3FE2|8FC8] [--port IDX DAT]\n"
"\n"
"Reads the BIOS master code for the given service tag + suffix family from\n"
"the machine's own EC (session sub 3 / type 6 GENERATE — CF1B_FINDINGS §11).\n"
"Default tag H2FS5S3, family CF1B. Bare metal, root.\n", argv[0]);
            return 1;
        }
    }

    if (!IO_INIT()) { perror("iopl (run as root on bare metal)"); return 1; }

    printf("Dell EC master-code reader — tag %s, family %04X\n", tag, family);
    printf("mailbox ports %03X/%03X, session 0x21 sub 3 type 6 (GENERATE)\n\n",
           PORT_IDX, PORT_DAT);

    unsigned char resp[32];
    int status = -1;
    int n = session_generate(tag, family, resp, &status);

    if (n < 0) {
        printf("session failed (%d): EC did not complete the GENERATE exchange.\n", n);
        printf(" - run on bare metal as root (VMs forward port I/O)\n");
        printf(" - if the mailbox is idle, the EC may gate type 6 by state\n");
        return 1;
    }
    dump("response (32B)", resp, n < 32 ? n : 32);
    printf("status byte        : %02X (%s)\n\n",
           status & 0xFF, status == 0 ? "success" :
           status == 0xFE ? "not delivered (session ended)" : "EC error code");

    if (n < 32) {
        printf("short response (%d bytes) — EC rejected the request.\n", n);
        return 1;
    }

    /* ---- CF1B / 3FE2 / 1B58 / 9ABE: fn 0x8E18 raw-copy branch --------- */
    printf("MASTER CODE (resp[0..15])  : ");
    for (int i = 0; i < 16; i++)
        putchar(resp[i] >= 0x20 && resp[i] < 0x7f ? resp[i] : '?');
    printf("\n");
    printf("second half  (resp[16..31]): ");
    for (int i = 16; i < 32; i++)
        putchar(resp[i] >= 0x20 && resp[i] < 0x7f ? resp[i] : '?');
    printf("   (challenge 'code 2' candidate)\n");

    /* ---- 8FC8: fn 0x8E18 dispatch branch, alphabet @0xa280 ------------ */
    if (family == 0x8FC8) {
        char m[17];
        for (int i = 0; i < 16; i++)
            m[i] = ALPHABET_EC[(resp[i] + resp[i + 16]) % 72];
        m[16] = 0;
        printf("8FC8 alphabet-mapped code : %s\n", m);
    }

    printf("\nEnter the MASTER CODE at the BIOS password prompt after the\n");
    printf("challenge screen shows the matching tag + suffix.\n");
    return 0;
}
