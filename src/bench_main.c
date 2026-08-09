/* Fidelio
 *
 * (c) 2023 Daniele Lacamera <root@danielinux.net>
 *
 * Fidelio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Fidelio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* wolfCrypt benchmark harness.
 *
 * Replaces the authenticator with wolfSSL's own benchmark, built against
 * Fidelio's user_settings.h so the numbers reflect the algorithms, curve set
 * and SP configuration the firmware actually ships.
 *
 * The board has no console, so benchmark output is captured into RAM and
 * written to a dedicated flash region on completion; read it back over USB in
 * BOOTSEL with
 *
 *   picotool save -r 0x101e0000 0x101e8000 bench.bin
 *
 * LED: blue while running, green when the results have been written, red if
 * the output overflowed the capture buffer.
 *
 * Build with -DFIDELIO_BENCH=ON. Clock is selectable with
 * -DFIDELIO_BENCH_CLOCK_KHZ= (default 48000, matching the firmware).
 */

#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "pico/stdlib.h"
#include "hardware/clocks.h"
#include "hardware/flash.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "flash_rt.h"
#include "puf_sram.h"
#include "indicator.h"
#include "pins.h"

extern int benchmark_test(void *args);

/* benchmark_test() picks ECC curves with an if/elif chain, so a build with
 * P-256 enabled never reaches P-384 or P-521, and its selection global is
 * static so it cannot be steered from here. Those curves are therefore timed
 * directly below, along with the figure that actually governs Fidelio's
 * latency budget: derive-then-sign, worst case rather than average.
 *
 * The worst case matters because ML-DSA signing is rejection-sampled, so its
 * cost varies run to run. Sizing a user-facing budget from a 4-iteration mean
 * would repeat the mistake of sizing the PUF profile from an average BER.
 */
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#ifdef WOLFSSL_HAVE_MLDSA
#include "wolfssl/wolfcrypt/wc_mldsa.h"
#endif

#define BENCH_FLASH_OFF   0x1E0000
#define BENCH_CAPTURE_SZ  (32 * 1024)

static char bench_buf[BENCH_CAPTURE_SZ];
static uint32_t bench_len = 0;
static int bench_overflow = 0;

/* benchmark.c is compiled with -Dprintf=bench_printf so its 380-odd printf
 * calls land here instead of a console that does not exist.
 */
int bench_printf(const char *fmt, ...)
{
    va_list ap;
    int n;
    uint32_t space;

    if (bench_len >= BENCH_CAPTURE_SZ - 1) {
        bench_overflow = 1;
        return 0;
    }
    space = BENCH_CAPTURE_SZ - bench_len;

    va_start(ap, fmt);
    n = vsnprintf(bench_buf + bench_len, space, fmt, ap);
    va_end(ap);

    if (n < 0)
        return n;
    if ((uint32_t)n >= space) {
        bench_len = BENCH_CAPTURE_SZ - 1;
        bench_overflow = 1;
    } else {
        bench_len += (uint32_t)n;
    }
    return n;
}

/* wolfSSL benchmark timing hook, enabled by WOLFSSL_USER_CURRTIME. */
double current_time(int reset)
{
    (void)reset;
    return (double)time_us_64() / 1000000.0;
}

/* --- Fidelio credential benchmark ------------------------------------------
 *
 * Times exactly what makeCredential/getAssertion do: derive a key from the
 * 32 bytes that come out of HMAC(master_secret, ...) and sign with it. Both
 * halves are reported, along with min/max, since the sum against a
 * sub-second budget is what decides which algorithms are usable.
 */

#define CRED_ITERS 12

/* Must cover the largest curve order: P-521 needs 66 bytes, P-384 48.
 * Sized at 66 so bench_ecdsa() never reads past the end -- doing so produced
 * an invalid scalar and a spurious P-521 "FAILED". */
static uint8_t cred_seed[66] = {
    0x5a, 0x3c, 0x71, 0x0e, 0x92, 0x44, 0xd8, 0x1b,
    0x6f, 0x27, 0xb5, 0x8a, 0x03, 0xe1, 0x4c, 0x96,
    0x2d, 0x78, 0xc4, 0x51, 0x9b, 0x36, 0xa0, 0x7f,
    0xe8, 0x12, 0x5d, 0xb3, 0x64, 0xcf, 0x29, 0x87,
    0x41, 0xda, 0x0b, 0x76, 0x35, 0xe9, 0x58, 0x1c,
    0xa7, 0x62, 0xfd, 0x30, 0x8e, 0x4b, 0xd5, 0x19,
    0x73, 0x2a, 0xc6, 0x0f, 0x9d, 0x54, 0xb8, 0x21,
    0x6e, 0xf3, 0x47, 0x0a, 0x85, 0xcb, 0x1f, 0x92,
    0x38, 0x6d,
};
static uint8_t cred_digest[32] = { 0xa5 };
static uint8_t cred_sig[5000];
#ifdef WOLFSSL_HAVE_MLDSA
/* 7.9 KB: far too large for the 2 KB core-0 stack, so it lives here. */
static wc_MlDsaKey cred_mldsa;
#endif

static void report(const char *name, const uint32_t *us, int n)
{
    uint32_t lo = 0xFFFFFFFFu, hi = 0, sum = 0;
    int i;
    for (i = 0; i < n; i++) {
        if (us[i] < lo) lo = us[i];
        if (us[i] > hi) hi = us[i];
        sum += us[i];
    }
    if (n == 0) { bench_printf("%-26s no samples\n", name); return; }
    bench_printf("%-26s avg %6lu ms   min %6lu ms   max %6lu ms\n", name,
                 (unsigned long)((sum / (uint32_t)n) / 1000),
                 (unsigned long)(lo / 1000), (unsigned long)(hi / 1000));
}

static void bench_ecdsa(const char *name, int curveId, int keySz, WC_RNG *rng)
{
    uint32_t gen[CRED_ITERS], sig[CRED_ITERS], both[CRED_ITERS];
    int i, ok = 0;

    for (i = 0; i < CRED_ITERS; i++) {
        ecc_key k;
        uint64_t t0, t1, t2;
        word32 sl = sizeof(cred_sig);

        if (wc_ecc_init(&k) != 0)
            break;
        t0 = time_us_64();
        /* Same shape as the firmware: import the derived scalar, then
         * compute the public point. */
        if (wc_ecc_import_private_key_ex(cred_seed, (word32)keySz, NULL, 0,
                                         &k, curveId) != 0 ||
            wc_ecc_make_pub(&k, NULL) != 0) {
            wc_ecc_free(&k);
            break;
        }
        t1 = time_us_64();
        if (wc_ecc_sign_hash(cred_digest, sizeof(cred_digest), cred_sig, &sl,
                             rng, &k) != 0) {
            wc_ecc_free(&k);
            break;
        }
        t2 = time_us_64();
        wc_ecc_free(&k);

        gen[ok] = (uint32_t)(t1 - t0);
        sig[ok] = (uint32_t)(t2 - t1);
        both[ok] = (uint32_t)(t2 - t0);
        ok++;
    }
    if (ok == 0) {
        bench_printf("%-26s FAILED\n", name);
        return;
    }
    bench_printf("%s (%d/%d ok)\n", name, ok, CRED_ITERS);
    report("  derive", gen, ok);
    report("  sign", sig, ok);
    report("  TOTAL", both, ok);
}

static void fidelio_credential_bench(void)
{
    WC_RNG rng;
    int i, ok;

    bench_printf("\n=== Fidelio credential path: derive + sign ===\n");
    bench_printf("(%d iterations each; TOTAL is what a makeCredential costs)\n",
                 CRED_ITERS);

    if (wc_InitRng(&rng) != 0) {
        bench_printf("RNG init failed\n");
        return;
    }

#ifdef HAVE_ECC256
    bench_ecdsa("ES256 / P-256", ECC_SECP256R1, 32, &rng);
#endif
#ifdef HAVE_ECC384
    bench_ecdsa("ES384 / P-384", ECC_SECP384R1, 48, &rng);
#endif
#ifdef HAVE_ECC521
    bench_ecdsa("ES512 / P-521", ECC_SECP521R1, 66, &rng);
#endif

#ifdef HAVE_ED25519
    {
        uint32_t gen[CRED_ITERS], sg[CRED_ITERS], both[CRED_ITERS];
        ok = 0;
        for (i = 0; i < CRED_ITERS; i++) {
            ed25519_key k;
            uint64_t t0, t1, t2;
            word32 sl = sizeof(cred_sig);
            uint8_t pub[32];
            if (wc_ed25519_init(&k) != 0) break;
            t0 = time_us_64();
            if (wc_ed25519_import_private_only(cred_seed, 32, &k) != 0 ||
                wc_ed25519_make_public(&k, pub, sizeof(pub)) != 0) {
                wc_ed25519_free(&k); break;
            }
            t1 = time_us_64();
            if (wc_ed25519_sign_msg(cred_digest, sizeof(cred_digest),
                                    cred_sig, &sl, &k) != 0) {
                wc_ed25519_free(&k); break;
            }
            t2 = time_us_64();
            wc_ed25519_free(&k);
            gen[ok] = (uint32_t)(t1 - t0);
            sg[ok] = (uint32_t)(t2 - t1);
            both[ok] = (uint32_t)(t2 - t0);
            ok++;
        }
        if (ok) {
            bench_printf("Ed25519 (%d/%d ok)\n", ok, CRED_ITERS);
            report("  derive", gen, ok);
            report("  sign", sg, ok);
            report("  TOTAL", both, ok);
        } else {
            bench_printf("Ed25519 FAILED\n");
        }
    }
#endif

#ifdef WOLFSSL_HAVE_MLDSA
    {
        static const struct { const char *name; int lvl; } sets[] = {
            { "ML-DSA-44", WC_ML_DSA_44 },
            { "ML-DSA-65", WC_ML_DSA_65 },
            { "ML-DSA-87", WC_ML_DSA_87 },
        };
        unsigned s;
        for (s = 0; s < sizeof(sets) / sizeof(sets[0]); s++) {
            uint32_t gen[CRED_ITERS], sg[CRED_ITERS], both[CRED_ITERS];
            ok = 0;
            for (i = 0; i < CRED_ITERS; i++) {
                uint64_t t0, t1, t2;
                word32 sl = sizeof(cred_sig);
                if (wc_MlDsaKey_Init(&cred_mldsa, NULL, INVALID_DEVID) != 0)
                    break;
                /* Vary the seed so rejection sampling is exercised rather
                 * than repeating one lucky draw. */
                cred_seed[0] = (uint8_t)i;
                t0 = time_us_64();
                if (wc_MlDsaKey_SetParams(&cred_mldsa, (byte)sets[s].lvl) != 0 ||
                    wc_MlDsaKey_MakeKeyFromSeed(&cred_mldsa, cred_seed) != 0) {
                    wc_MlDsaKey_Free(&cred_mldsa); break;
                }
                t1 = time_us_64();
                if (wc_MlDsaKey_SignCtx(&cred_mldsa, NULL, 0, cred_sig, &sl,
                                        cred_digest, sizeof(cred_digest),
                                        &rng) != 0) {
                    wc_MlDsaKey_Free(&cred_mldsa); break;
                }
                t2 = time_us_64();
                wc_MlDsaKey_Free(&cred_mldsa);
                gen[ok] = (uint32_t)(t1 - t0);
                sg[ok] = (uint32_t)(t2 - t1);
                both[ok] = (uint32_t)(t2 - t0);
                ok++;
            }
            if (ok) {
                bench_printf("%s (%d/%d ok)\n", sets[s].name, ok, CRED_ITERS);
                report("  derive", gen, ok);
                report("  sign", sg, ok);
                report("  TOTAL", both, ok);
            } else {
                bench_printf("%s FAILED\n", sets[s].name);
            }
        }
    }
#endif

    wc_FreeRng(&rng);
}

int main(void)
{
    uint32_t written;

    /* Keep the PUF region read intact even here: custom_random_seed() mixes
     * it into the DRBG seed, and the benchmark exercises the RNG.
     */
    puf_sram_snapshot();

    set_sys_clock_khz(FIDELIO_BENCH_CLOCK_KHZ, true);
    indicator_init();
    indicator_set(0, 0, 0x30);

    bench_printf("fidelio wolfcrypt benchmark\n");
    bench_printf("sys clock: %lu Hz\n", (unsigned long)clock_get_hz(clk_sys));
    bench_printf("---\n");

    (void)benchmark_test(NULL);

    fidelio_credential_bench();

    bench_printf("\n--- end (%lu bytes%s) ---\n", (unsigned long)bench_len,
                 bench_overflow ? ", TRUNCATED" : "");

    /* Persist. Round up to a sector so the erase covers everything written. */
    written = (bench_len + FLASH_SECTOR_SIZE) & ~(FLASH_SECTOR_SIZE - 1);
    if (written > BENCH_CAPTURE_SZ)
        written = BENCH_CAPTURE_SZ;
    fidelio_flash_erase(BENCH_FLASH_OFF, written);
    fidelio_flash_program(BENCH_FLASH_OFF, bench_buf, written);

    indicator_set(bench_overflow ? 0x30 : 0, bench_overflow ? 0 : 0x30, 0);
    while (1) {
        tight_loop_contents();
    }
}
