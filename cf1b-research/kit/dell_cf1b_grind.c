/*
 * dell_cf1b_grind.c — CF1B-exclusive password search (no legacy algorithm).
 *
 * Implements CF1B's own acceptance chain (CF1B_FINDINGS.md §2, confirmed at
 * instruction level in the OptiPlex 3090 2.27.0/2.30.0 pw_4 module and
 * validated against the real firmware fn 0x1BB4 under unicorn by
 * dell_cf1b_r.py --selftest):
 *
 *     X = SHA256(pw[0..16] || salt)      salt = 8D FC 7B 25 (raw bytes)
 *     Y = SHA256(X || salt)
 *     the BIOS accepts pw  iff  EC's R == Y
 *
 * R is readable on the authorized machine with dell_cf1b_probe.c (it is
 * returned by the EC before the PASS/FAIL comparison). This tool searches
 * for pw given R.
 *
 * Both hashed messages (16+4 = 20 B and 32+4 = 36 B) fit a single SHA-256
 * block, so each candidate costs exactly 2 compressions.
 *
 * Build:   gcc -O3 -march=native -pthread -o dell_cf1b_grind dell_cf1b_grind.c
 * Cross-check with the firmware-validated Python (both must print same Y):
 *     ./dell_cf1b_grind --verify TestPw123
 *     python3 dell_cf1b_r.py --pw TestPw123
 *
 * Usage:
 *   ./dell_cf1b_grind <R_hex> [--charset <s>] [--maxlen <n>] [--threads <n>]
 *   ./dell_cf1b_grind --verify <password>        # print X and Y
 *   ./dell_cf1b_grind <R_hex> --list < file      # wordlist mode (one pw/line)
 *   ./dell_cf1b_grind --bench                    # single-core rate
 *
 * For recovery of machines you own or are authorized to service.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#define MAXPW 16
static const uint8_t SALT[4] = { 0x8d, 0xfc, 0x7b, 0x25 };

/* ------------------------------------------------------------------ */
/* SHA-256 compression (standard, public-domain formulation)           */
/* ------------------------------------------------------------------ */
static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static const uint32_t H0[8] = {
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
};
#define ROTR32(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(uint32_t st[8], const uint8_t b[64])
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)b[4*i] << 24) | ((uint32_t)b[4*i+1] << 16) |
               ((uint32_t)b[4*i+2] << 8) | (uint32_t)b[4*i+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROTR32(w[i-15],7) ^ ROTR32(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROTR32(w[i-2],17) ^ ROTR32(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=st[0],b_=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROTR32(e,6) ^ ROTR32(e,11) ^ ROTR32(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = ROTR32(a,2) ^ ROTR32(a,13) ^ ROTR32(a,22);
        uint32_t mj = (a & b_) ^ (a & c) ^ (b_ & c);
        uint32_t t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b_; b_=a; a=t1+t2;
    }
    st[0]+=a; st[1]+=b_; st[2]+=c; st[3]+=d; st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
}

static void words_to_bytes(const uint32_t st[8], uint8_t out[32])
{
    for (int i = 0; i < 8; i++) {
        out[4*i]   = (uint8_t)(st[i] >> 24);
        out[4*i+1] = (uint8_t)(st[i] >> 16);
        out[4*i+2] = (uint8_t)(st[i] >> 8);
        out[4*i+3] = (uint8_t)(st[i]);
    }
}

/* The CF1B chain: exactly two compressions per candidate. */
static inline void cf1b_Y(const uint8_t pw[MAXPW], uint8_t Y[32])
{
    uint8_t b1[64], b2[64];
    uint32_t st[8];

    /* block 1: pw16 || salt || pad || len(160 bits = 0xA0) */
    memset(b1, 0, 64);
    memcpy(b1, pw, MAXPW);
    memcpy(b1 + 16, SALT, 4);
    b1[20] = 0x80;
    b1[63] = 0xA0;
    memcpy(st, H0, sizeof st);
    sha256_block(st, b1);
    words_to_bytes(st, b2);                       /* X into block 2 */

    /* block 2: X || salt || pad || len(288 bits = 0x120) */
    memcpy(b2 + 32, SALT, 4);
    memset(b2 + 36, 0, 28);
    b2[36] = 0x80;
    b2[62] = 0x01;
    b2[63] = 0x20;
    memcpy(st, H0, sizeof st);
    sha256_block(st, b2);
    words_to_bytes(st, Y);
}

static void pw_to16(const char *pw, size_t len, uint8_t out[MAXPW])
{
    memset(out, 0, MAXPW);
    if (len > MAXPW) len = MAXPW;
    memcpy(out, pw, len);
}

/* ------------------------------------------------------------------ */
/* Search state                                                        */
/* ------------------------------------------------------------------ */
static char     charset[128];
static int      C;
static int      maxlen;
static uint8_t  R[32];
static volatile int found = 0;
static char     found_pw[MAXPW + 1];
static pthread_mutex_t found_mu = PTHREAD_MUTEX_INITIALIZER;
static volatile unsigned long long tried_total = 0;

static int nthreads = 0;      /* 0 = auto (all online cores) */

static int test_pw(const char *pw, size_t len)
{
    uint8_t p16[MAXPW], Y[32];
    pw_to16(pw, len, p16);
    cf1b_Y(p16, Y);
    if (Y[0] == R[0] && memcmp(Y, R, 32) == 0) {
        pthread_mutex_lock(&found_mu);
        memcpy(found_pw, pw, len);
        found_pw[len] = 0;
        found = 1;
        pthread_mutex_unlock(&found_mu);
        return 1;
    }
    return 0;
}

/* Search all passwords of length n; this thread takes jobs j ≡ tid (mod nthreads). */
static void grind_len(int n, int tid, unsigned long long *tried)
{
    /* prefix depth k: smallest k with C^k >= nthreads (or k = n) */
    int k = 1;
    while (k < n) {
        unsigned long long jobs = 1;
        for (int i = 0; i < k; i++) jobs *= (unsigned long long)C;
        if (jobs >= (unsigned long long)nthreads) break;
        k++;
    }
    unsigned long long njobs = 1;
    for (int i = 0; i < k; i++) njobs *= (unsigned long long)C;
    int m = n - k;

    for (unsigned long long j = tid; j < njobs && !found; j += (unsigned long long)nthreads) {
        char pw[MAXPW + 1];
        uint8_t idx[MAXPW];
        unsigned long long t = j;
        for (int i = k - 1; i >= 0; i--) { idx[i] = t % (unsigned)C; t /= (unsigned)C; }
        for (int i = 0; i < k; i++) pw[i] = charset[idx[i]];
        if (m == 0) {
            (*tried)++;
            if (test_pw(pw, n)) return;
            continue;
        }
        for (int i = 0; i < m; i++) { pw[k + i] = charset[0]; idx[k + i] = 0; }
        for (;;) {
            (*tried)++;
            if (test_pw(pw, n)) return;
            if (found) return;
            int i = m - 1;
            while (i >= 0 && ++idx[k + i] == C) { idx[k + i] = 0; pw[k + i] = charset[0]; i--; }
            if (i < 0) break;
            pw[k + i] = charset[idx[k + i]];
        }
    }
}

typedef struct { int tid; } targ;

static void *worker(void *arg)
{
    int tid = ((targ *)arg)->tid;
    unsigned long long tried = 0;
    for (int n = 1; n <= maxlen && !found; n++)
        grind_len(n, tid, &tried);
    __sync_fetch_and_add(&tried_total, tried);
    return NULL;
}

int main(int argc, char **argv)
{
    const char *cs = "abcdefghijklmnopqrstuvwxyz0123456789";
    const char *rhex = NULL, *verify = NULL;
    int bench = 0, listmode = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--charset") && i + 1 < argc) cs = argv[++i];
        else if (!strcmp(argv[i], "--maxlen") && i + 1 < argc) maxlen = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--threads") && i + 1 < argc) nthreads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--verify") && i + 1 < argc) verify = argv[++i];
        else if (!strcmp(argv[i], "--bench")) bench = 1;
        else if (!strcmp(argv[i], "--list")) listmode = 1;
        else if (argv[i][0] != '-' && !rhex) rhex = argv[i];
    }

    if (verify) {
        uint8_t p16[MAXPW], X[32], Y[32];
        size_t len = strlen(verify);
        if (len > MAXPW) { fprintf(stderr, "password > 16 chars\n"); return 1; }
        char hx[65], hy[65];
        pw_to16(verify, len, p16);
        uint8_t b1[64]; uint32_t st[8];
        memset(b1, 0, 64); memcpy(b1, p16, MAXPW); memcpy(b1 + 16, SALT, 4);
        b1[20] = 0x80; b1[63] = 0xA0;
        memcpy(st, H0, sizeof st); sha256_block(st, b1);
        words_to_bytes(st, X);
        cf1b_Y(p16, Y);
        static const char hc[] = "0123456789abcdef";
        for (int i = 0; i < 32; i++) {
            hx[2*i]=hc[X[i]>>4]; hx[2*i+1]=hc[X[i]&15];
            hy[2*i]=hc[Y[i]>>4]; hy[2*i+1]=hc[Y[i]&15];
        }
        hx[64]=hy[64]=0;
        printf("pw   = %s\nX    = %s\nY    = %s\n", verify, hx, hy);
        return 0;
    }

    if (bench) {
        struct timespec t0, t1;
        uint8_t p16[MAXPW], Y[32];
        pw_to16("benchbenchbench1", 16, p16);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        unsigned long long iters = 20000000, dummy = 0;
        for (unsigned long long i = 0; i < iters; i++) {
            p16[0] = (uint8_t)i; p16[1] = (uint8_t)(i >> 8);
            cf1b_Y(p16, Y);
            dummy += Y[0];
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double sec = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
        printf("single-core: %.2f M candidates/s (dummy=%llu)\n",
               iters / sec / 1e6, dummy & 1);
        return 0;
    }

    if (!rhex || strlen(rhex) != 64) {
        fprintf(stderr, "usage: %s <R_hex 64 chars> [--charset s] [--maxlen n] "
                "[--threads n] | --verify pw | --bench | --list < wordlist\n",
                argv[0]);
        return 1;
    }
    for (int i = 0; i < 32; i++) {
        unsigned v;
        if (sscanf(rhex + 2*i, "%2x", &v) != 1) { fprintf(stderr, "bad hex\n"); return 1; }
        R[i] = (uint8_t)v;
    }

    /* dedupe charset */
    int seen[256] = {0};
    C = 0;
    for (const char *p = cs; *p && C < 127; p++)
        if (!seen[(unsigned char)*p]) { seen[(unsigned char)*p] = 1; charset[C++] = *p; }
    charset[C] = 0;
    if (maxlen <= 0) maxlen = 7;
    if (maxlen > MAXPW) { maxlen = MAXPW; fprintf(stderr, "maxlen capped at 16\n"); }

    if (test_pw("", 0)) { printf("FOUND: (empty password)\n"); return 0; }

    if (listmode) {
        char line[512];
        unsigned long long n = 0;
        while (fgets(line, sizeof line, stdin)) {
            size_t l = strlen(line);
            while (l && (line[l-1] == '\n' || line[l-1] == '\r')) line[--l] = 0;
            if (l == 0 || l > MAXPW) continue;
            n++;
            if (test_pw(line, l)) { printf("FOUND: %s  (%llu tried)\n", found_pw, n); return 0; }
        }
        printf("not found (%llu words tried)\n", n);
        return 1;
    }

    if (nthreads <= 0) {
        long nc = sysconf(_SC_NPROCESSORS_ONLN);
        nthreads = nc > 0 ? (int)nc : 1;
    }
    if (nthreads > 256) nthreads = 256;
    fprintf(stderr, "CF1B grind: charset=%d chars '%s', maxlen=%d, threads=%d\n",
            C, charset, maxlen, nthreads);
    fprintf(stderr, "R = %s\n", rhex);

    pthread_t th[256];
    targ tids[256];
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < nthreads; i++) { tids[i].tid = i; pthread_create(&th[i], NULL, worker, &tids[i]); }
    for (int i = 0; i < nthreads; i++) pthread_join(th[i], NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double sec = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

    if (found) {
        printf("FOUND: password = %s   (%.2f s, %llu candidates)\n",
               found_pw, sec, tried_total);
        return 0;
    }
    printf("not found (%llu candidates, %.2f s, %.2f M/s)\n",
           tried_total, sec, tried_total / sec / 1e6);
    return 1;
}
