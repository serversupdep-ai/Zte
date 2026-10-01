/*
 * dell_8fc8_probe.c — Dell 8FC8 BIOS-password challenge mailbox probe.
 *
 * Talks the Dell EC/SMM mailbox at I/O ports 0x910 (index) / 0x911 (data)
 * directly, replicating what the BIOS password module does for the 8FC8
 * family (command 0x21), and dumps the 32-byte response.
 *
 * The protocol below was reverse-engineered from the OptiPlex 3090 2.0.7
 * firmware (see bios-analysis/REPORT.md §10):
 *
 *   - Port 0x910 selects a register, port 0x911 reads/writes its value.
 *   - Register 0x00 (selector 0x00) = command doorbell: write the command
 *     byte, then poll (select 0x00, read 0x911) until it returns 0 (ACK).
 *   - Selectors 0x10..0x2F map to a 32-byte message window
 *     (window byte i <-> selector 0x10+i):
 *       win[0], win[1] : reserved
 *       win[2]         : flags / sub-command
 *       win[3]         : count / platform type
 *       win[4..11]     : packet payload (max 8 bytes per packet)
 *   - Command 0x17 = data transfer. Write: set win[2]=0, win[3]=0, doorbell
 *     0x17, then per 8-byte chunk: write chunk to win[4..], win[3]=chunk_len,
 *     win[2]=1, poll ACK, then wait win[2] bit0 == 0 (consumed); finish with
 *     an empty packet (win[3]=0, win[2]=1) and read back win[0..15].
 *     Read: set win[2]=0, win[3]=0, doorbell 0x17, then loop: wait win[2]
 *     bit0 == 1, count = win[3], read count bytes from win[4..], clear
 *     win[3]=0, win[2]=0, until all bytes received.
 *   - Command 0x21 (8FC8 challenge): write win[2]=1 (sub), win[3]=platform
 *     type (0..6; type 3 additionally receives the 16-bit family code),
 *     doorbell 0x21, poll ACK, then send the 16-byte challenge value via
 *     0x17-write packets, then read 32 bytes back via 0x17-read packets.
 *
 * The BIOS compares the first 16 response bytes against a stored config
 * value and discards the rest — but any code with port I/O access can read
 * the whole response. If the response is independent of the 16-byte input,
 * it IS the machine's expected 8FC8 key material.
 *
 * Build (Linux):  gcc -O2 -o dell_8fc8_probe dell_8fc8_probe.c
 * Run (Linux):    sudo ./dell_8fc8_probe            (needs iopl())
 * FreeDOS:        gcc -DJOS -o probe.exe dell_8fc8_probe.c  (DJGPP/BC)
 *                  or use the outp()/inp() variant below.
 *
 * This is for recovery of machines you own / are authorized to service.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#if defined(__linux__)
#include <sys/io.h>            /* iopl()  — compile with -O2 on x86 only */
static inline void outportb(unsigned short p, unsigned char v) { __asm__ volatile("outb %0,%1"::"a"(v),"Nd"(p)); }
static inline unsigned char inportb(unsigned short p) { unsigned char r; __asm__ volatile("inb %1,%0":"=a"(r):"Nd"(p)); return r; }
#define IO_INIT() (iopl(3) == 0)
#elif defined(DOS) /* DJGPP */
#include <pc.h>
#define outportb outp
#define inportb inp
#define IO_INIT() 1
#elif defined(_WIN32) /* needs a kernel driver such as WinIo/InpOut32; see python driver */
#error "On Windows use the python driver with WinIo/InpOut32, or a small KMDF driver"
#else
#error "unsupported platform"
#endif

#define PORT_IDX 0x910
#define PORT_DAT 0x911
#define WIN_BASE 0x10          /* selector base of the 32-byte window    */
#define SEL_CMD  0x00          /* doorbell / ack                         */
#define TIMEOUT  2000000

static void sel(unsigned char s)          { outportb(PORT_IDX, s); }
static void wdat(unsigned char v)         { outportb(PORT_DAT, v); }
static unsigned char rdat(void)           { return inportb(PORT_DAT); }

static void win_write(unsigned i, unsigned char v) { sel(WIN_BASE + i); wdat(v); }
static unsigned char win_read(unsigned i)          { sel(WIN_BASE + i); return rdat(); }

/* wait for doorbell ACK: select 0x00, read until 0 */
static int wait_ack(void)
{
    for (long t = 0; t < TIMEOUT; t++) {
        sel(SEL_CMD);
        if (rdat() == 0)
            return 0;
    }
    return -1;
}

/* doorbell a command byte */
static int doorbell(unsigned char cmd)
{
    sel(SEL_CMD); wdat(cmd);
    sel(SEL_CMD);
    return wait_ack();
}

/* --- command 0x17 write: send len bytes as <=8-byte packets --- */
static int xfer_write(const unsigned char *data, int len)
{
    int off = 0;
    /* clear header */
    win_write(3, 0); win_write(2, 0);
    if (doorbell(0x17) != 0) return -1;

    while (off < len) {
        int n = len - off > 8 ? 8 : len - off;
        for (int i = 0; i < n; i++)
            win_write(4 + i, data[off + i]);
        win_write(3, (unsigned char)n);
        win_write(2, 1);
        if (wait_ack() != 0) return -1;
        /* wait consumed: win[2] bit0 clears */
        for (long t = 0; t < TIMEOUT; t++) {
            if ((win_read(2) & 1) == 0) break;
            if (t == TIMEOUT - 1) return -1;
        }
        off += n;
    }
    /* end-of-transfer empty packet */
    win_write(3, 0); win_write(2, 1);
    if (wait_ack() != 0) return -1;
    return 0;
}

/* --- command 0x17 read: receive len bytes --- */
static int xfer_read(unsigned char *out, int len)
{
    int got = 0;
    win_write(3, 0); win_write(2, 0);
    if (doorbell(0x17) != 0) return -1;

    while (got < len) {
        /* wait packet ready: win[2] bit0 set */
        unsigned char cnt = 0;
        for (long t = 0; t < TIMEOUT; t++) {
            if (win_read(2) & 1) { cnt = win_read(3); break; }
            if (t == TIMEOUT - 1) return -1;
        }
        if (cnt == 0) break;                    /* end of stream */
        if (cnt > 8) cnt = 8;
        if (cnt > len - got) cnt = (unsigned char)(len - got);
        for (int i = 0; i < cnt; i++)
            out[got + i] = win_read(4 + i);
        got += cnt;
        win_write(3, 0); win_write(2, 0);       /* consumed */
    }
    return got;
}

/* --- 8FC8 challenge (cmd 0x21) --- */
static int challenge_8fc8(int type, const unsigned char x16[16],
                          unsigned char resp[32])
{
    /* window header: sub-command 1, platform type */
    win_write(2, 1);
    win_write(3, (unsigned char)type);
    if (doorbell(0x21) != 0) return -1;

    if (xfer_write(x16, 16) != 0) return -2;
    if (type == 3) {                            /* family code follows */
        unsigned char fam[2] = { 0xC8, 0x8F };  /* 0x8FC8 LE */
        if (xfer_write(fam, 2) != 0) return -3;
    }
    return xfer_read(resp, 32);
}

static void dump(const char *label, const unsigned char *b, int n)
{
    printf("%-18s ", label);
    for (int i = 0; i < n; i++) printf("%02x", b[i]);
    printf("  |");
    for (int i = 0; i < n; i++)
        putchar(b[i] >= 0x20 && b[i] < 0x7f ? b[i] : '.');
    printf("|\n");
}

int main(void)
{
    if (!IO_INIT()) { perror("iopl"); fprintf(stderr,
        "run as root on bare metal (not inside a VM — VMs usually trap 0x910)\n"); return 1; }

    puts("Dell 8FC8 challenge probe — ports 0x910/0x911, command 0x21");
    puts("(recovery tool for machines you own; see REPORT.md §10)\n");

    unsigned char zero[16]  = {0};
    unsigned char randx[16] = {0xDE,0xAD,0xBE,0xEF,0x01,0x23,0x45,0x67,
                               0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98};
    unsigned char r_zero[32], r_rand[32];

    for (int type = 0; type <= 6; type++) {
        int n1 = challenge_8fc8(type, zero, r_zero);
        if (n1 < 0) { printf("type %d: no response (%d)\n", type, n1); continue; }
        int n2 = challenge_8fc8(type, randx, r_rand);
        printf("platform type %d:\n", type);
        dump("  resp(X=00..)", r_zero, n1);
        if (n2 > 0) dump("  resp(X=rand)", r_rand, n2);
        if (n2 > 0 && memcmp(r_zero, r_rand, 16) == 0 && memcmp(r_zero, zero, 16) != 0) {
            puts("  >>> ORACLE CONFIRMED: response independent of input.");
            puts("  >>> First 16 bytes are this machine's expected 8FC8 value.");
        } else if (n2 > 0 && memcmp(r_zero, randx, 16) == 0) {
            puts("  >>> Echo mode: pure verifier — response mirrors the input.");
        }
        putchar('\n');
    }
    puts("If the response contains printable ASCII, try it directly at the");
    puts("BIOS password prompt. If binary, feed the first 16 bytes to:");
    puts("  python3 bios-analysis/dell_keygen.py --interpret8fc8 <hex>");
    return 0;
}
