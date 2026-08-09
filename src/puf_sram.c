/* Fidelio
 *
 * (c) 2023 Daniele Lacamera <root@danielinux.net>
 *
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
 *
 */

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "pico/stdlib.h"
#include "hardware/flash.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/puf.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "puf_sram.h"
#include "indicator.h"

extern void ForceZero(void* mem, word32 len);

/* Checkpoint sector. Reuses the sector that held the stored master key before
 * the PUF was introduced, so the flash map is unchanged.
 */
#define FLASH_PUF_OFF      0x72000
#define FLASH_PUF_ADDR     ((const uint8_t *)(XIP_BASE + FLASH_PUF_OFF))

/* Enrollment is committed in two steps. 'PUF0' means helper data has been
 * written but never proven to reconstruct; 'PUF1' means a cold boot has
 * reproduced the same stable bits from it. Nothing is registered against the
 * device until it reaches 'PUF1', so discarding a 'PUF0' checkpoint is free.
 */
#define PUF_MAGIC_PROVISIONAL 0x50554630u /* 'PUF0' */
#define PUF_MAGIC_COMMITTED   0x50554631u /* 'PUF1' */

/* Halt codes, blinked as N short flashes followed by a pause. The stock Pico
 * has a single LED, so a countable pattern carries further than a colour.
 */
#define PUF_CODE_ENROLLED     1 /* enrolled, power-cycle to verify */
#define PUF_CODE_RECONSTRUCT  2 /* reconstruction failed, power-cycle to retry */
#define PUF_CODE_CONFIG       3 /* build or memory-map fault, not retryable */

/* HKDF info: a fixed label binding the key to this use, followed by a salt
 * drawn once per enrollment.
 *
 * The salt is what makes a factory reset meaningful. SRAM keeps its contents
 * across a warm reset, so a reset that rebooted through the watchdog would
 * re-measure the identical response and re-enrollment would reproduce the
 * very same master secret. Re-salting guarantees a new secret regardless of
 * how the device restarted. The salt is not secret and is stored in the
 * clear next to the helper data.
 */
#define PUF_SALT_SZ 32
static const char puf_key_label[] = "fidelio-master-secret";

/* The reserved SRAM response. Placed by src/memmap_fidelio.ld at the base of
 * SCRATCH_X in a NOLOAD section: never initialised, never written.
 */
static volatile const uint8_t puf_region[WC_PUF_RAW_BYTES]
    __attribute__((section(".puf_sram"), used));

/* Linker-provided bounds, used to prove at runtime that nothing else in the
 * image was placed on top of the response region. src/memmap_fidelio.ld puts
 * .puf_sram first in SCRATCH_X so .scratch_x data is displaced above it, and
 * core 1's stack (which would grow down from the top of the bank) is absent
 * because pico_multicore is not linked -- these check both still hold.
 */
extern uint8_t __puf_sram_start__[];
extern uint8_t __puf_sram_end__[];
extern uint8_t __scratch_x_start__[];
extern uint8_t __StackOneBottom[];

static uint8_t puf_raw[WC_PUF_RAW_BYTES];
static uint8_t master_secret[WC_PUF_KEY_SZ];
static bool snapshot_taken = false;
static bool secret_valid = false;

/* profileId records the BCH profile, codeword count, hash and helper layout
 * the helper data was enrolled with. wc_PufReconstructEx() refuses to run
 * against a mismatch, which would otherwise decode to a silently wrong key --
 * a firmware update that changed WC_PUF_BCH_T would quietly invalidate every
 * credential with no error anywhere.
 */
struct puf_checkpoint {
    uint32_t magic;
    uint32_t profileId;
    uint8_t salt[PUF_SALT_SZ];
    uint8_t helper[WC_PUF_HELPER_BYTES];
};

/* flash_range_program() writes whole pages. */
#define PUF_PAGE_SPAN (((sizeof(struct puf_checkpoint) + FLASH_PAGE_SIZE - 1) \
                        / FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE)

void puf_sram_snapshot(void)
{
    if (snapshot_taken)
        return;
    for (uint32_t i = 0; i < WC_PUF_RAW_BYTES; i++)
        puf_raw[i] = puf_region[i];
    snapshot_taken = true;
}

const uint8_t *puf_raw_response(uint32_t *len)
{
    if (len)
        *len = WC_PUF_RAW_BYTES;
    return puf_raw;
}

const uint8_t *puf_master_secret(void)
{
    return secret_valid ? master_secret : NULL;
}

/* Blink a halt code forever: `code` short flashes, then a long pause. The
 * caller has already run indicator_init(); re-running it would add a second
 * copy of the WS2812 PIO program on RGB boards.
 */
static void puf_halt(int code, uint16_t r, uint16_t g, uint16_t b)
{
    while (1) {
        for (int i = 0; i < code; i++) {
            indicator_set(r, g, b);
            sleep_ms(180);
            indicator_set_idle();
            sleep_ms(220);
        }
        sleep_ms(1400);
    }
}

static void __not_in_flash_func(puf_write_checkpoint)(uint32_t magic,
                                                      const uint8_t *salt,
                                                      const uint8_t *helper)
{
    uint8_t page[PUF_PAGE_SPAN];
    struct puf_checkpoint *cp = (struct puf_checkpoint *)page;

    memset(page, 0xFF, sizeof(page));
    cp->magic = magic;
    cp->profileId = (uint32_t)WC_PUF_PROFILE_ID;
    memcpy(cp->salt, salt, PUF_SALT_SZ);
    memcpy(cp->helper, helper, WC_PUF_HELPER_BYTES);
    flash_range_erase(FLASH_PUF_OFF, FLASH_SECTOR_SIZE);
    flash_range_program(FLASH_PUF_OFF, page, sizeof(page));
    ForceZero(page, sizeof(page));
}

void __not_in_flash_func(puf_factory_erase)(void)
{
    flash_range_erase(FLASH_PUF_OFF, FLASH_SECTOR_SIZE);
    ForceZero(master_secret, sizeof(master_secret));
    secret_valid = false;
}

static int puf_derive(wc_PufCtx *ctx, const uint8_t *salt)
{
    uint8_t info[sizeof(puf_key_label) - 1 + PUF_SALT_SZ];
    int ret;

    memcpy(info, puf_key_label, sizeof(puf_key_label) - 1);
    memcpy(info + sizeof(puf_key_label) - 1, salt, PUF_SALT_SZ);
    ret = wc_PufDeriveKey(ctx, info, (word32)sizeof(info),
                          master_secret, sizeof(master_secret));
    ForceZero(info, sizeof(info));
    if (ret != 0)
        return -1;
    secret_valid = true;
    return 0;
}

static int puf_make_salt(uint8_t *salt)
{
    WC_RNG rng;
    int ret;

    if (wc_InitRng(&rng) != 0)
        return -1;
    ret = wc_RNG_GenerateBlock(&rng, salt, PUF_SALT_SZ);
    wc_FreeRng(&rng);
    return (ret == 0) ? 0 : -1;
}

#ifdef FIDELIO_PUF_DIAG
#include <stdio.h>

/* --- Bring-up diagnostic log ---------------------------------------------
 *
 * The measurement that decides whether the configured BCH profile is right
 * for a given board is the per-codeword bit error rate: how far each boot's
 * SRAM reading drifts from the one that was enrolled. Reconstruction fails
 * when any single 127-bit codeword drifts by more than WC_PUF_BCH_T bits.
 *
 * Collecting that needs many power cycles, and a Pico has no console unless
 * a UART adapter is wired up. So each run appends a record to a flash log and
 * reports a verdict on the LED; the whole series is read out afterwards with
 *
 *   picotool save -r 0x101ff000 0x10200000 log.bin
 *
 * (hold BOOT while plugging in to get into BOOTSEL first).
 */
#define FLASH_DIAG_OFF   0x1FF000   /* last sector of a 2 MB part */
#define FLASH_DIAG_ADDR  ((const uint8_t *)(XIP_BASE + FLASH_DIAG_OFF))
#define DIAG_MAGIC       0x504C4732u /* 'PLG2' */
#define DIAG_MAX_REC     100

/* Per-codeword distances are recorded, not just the worst one. Whether the
 * errors concentrate in the same few blocks every boot or wander decides
 * whether a marginal board is a placement problem (move the region) or a
 * physics problem (accept the retry).
 */
struct puf_diag_rec {
    uint16_t seq;
    uint16_t weight;    /* bits set in this boot's response */
    uint16_t dist;      /* total Hamming distance from the reference */
    uint16_t max_cw;    /* worst single-codeword distance, of 127 */
    uint16_t over_t;    /* codewords that exceeded WC_PUF_BCH_T */
    uint8_t  recon_ok;  /* wc_PufReconstructEx() succeeded */
    uint8_t  cp_state;  /* checkpoint magic seen: 0 none, 1 prov, 2 committed */
    uint8_t  cw[WC_PUF_NUM_CODEWORDS]; /* distance per codeword */
    uint32_t reserved;
};

struct puf_diag_log {
    uint32_t magic;
    uint16_t count;
    uint16_t bch_t;
    uint16_t ncw;
    uint16_t raw_bytes;
    uint8_t  pad[20];
    uint8_t  reference[WC_PUF_RAW_BYTES];
    struct puf_diag_rec rec[DIAG_MAX_REC];
};

/* diag_log_save() copies this wholesale into a sector-sized stack buffer. */
_Static_assert(sizeof(struct puf_diag_log) <= FLASH_SECTOR_SIZE,
               "diagnostic log does not fit in one flash sector");

static struct puf_diag_log diag_log;

static uint32_t popcount8(uint8_t v)
{
    uint32_t n = 0;
    while (v) { n += (v & 1u); v >>= 1; }
    return n;
}

/* Distance over the 127 bits codeword `cw` actually uses. Bits are packed
 * MSB-first, so bit 127 is the low bit of the last byte and is not part of
 * the codeword.
 */
static uint32_t codeword_distance(const uint8_t *a, const uint8_t *b, int cw)
{
    const uint8_t *pa = a + (cw * 16);
    const uint8_t *pb = b + (cw * 16);
    uint32_t d = 0;
    for (int i = 0; i < 15; i++)
        d += popcount8((uint8_t)(pa[i] ^ pb[i]));
    d += popcount8((uint8_t)((pa[15] ^ pb[15]) & 0xFEu));
    return d;
}

static void __not_in_flash_func(diag_log_save)(void)
{
    uint8_t page[FLASH_SECTOR_SIZE];
    memset(page, 0xFF, sizeof(page));
    memcpy(page, &diag_log, sizeof(diag_log));
    flash_range_erase(FLASH_DIAG_OFF, FLASH_SECTOR_SIZE);
    flash_range_program(FLASH_DIAG_OFF, page, sizeof(page));
}

/* Bring-up diagnostic. Reconstruction fails if any single 127-bit codeword
 * carries more than WC_PUF_BCH_T flipped bits, and the margin shrinks at
 * temperature extremes and varies between chips, so a board should be
 * qualified before any credential is registered against it.
 *
 * Build with -DFIDELIO_PUF_DIAG=ON, run over a dozen or more power cycles
 * across the temperature range the key will see, and confirm reconstruction
 * succeeds every time.
 */
/* Show the verdict and stay lit, so the operator can just unplug and replug.
 * Colours are chosen to be readable at a glance on the RGB boards:
 *   blue   first run, reference captured
 *   green  comfortable margin
 *   amber  inside the correction limit but close to it
 *   red    would have failed to reconstruct
 *   white  log full
 */
static void diag_verdict(uint32_t max_cw, bool first)
{
    if (first)
        indicator_set(0, 0, 0x30);
    else if (max_cw > WC_PUF_BCH_T)
        indicator_set(0x30, 0, 0);
    else if (max_cw * 3 >= (uint32_t)WC_PUF_BCH_T * 2)
        indicator_set(0x30, 0x18, 0);
    else
        indicator_set(0, 0x30, 0);
    while (1) { tight_loop_contents(); }
}

void puf_diag_report(void)
{
    const struct puf_checkpoint *cp = (const struct puf_checkpoint *)FLASH_PUF_ADDR;
    const struct puf_diag_log *stored = (const struct puf_diag_log *)FLASH_DIAG_ADDR;
    wc_PufCtx ctx;
    struct puf_diag_rec rec;
    int m, n, k, t, ncw;
    uint32_t i;
    uint32_t weight = 0, dist = 0, max_cw = 0, over_t = 0;
    bool first = false;

    stdio_init_all();
    sleep_ms(200);

    puf_sram_snapshot();

    /* ---- measure ---- */
    for (i = 0; i < WC_PUF_RAW_BYTES; i++)
        weight += popcount8(puf_raw[i]);

    memcpy(&diag_log, stored, sizeof(diag_log));
    if (diag_log.magic != DIAG_MAGIC || diag_log.raw_bytes != WC_PUF_RAW_BYTES ||
        diag_log.bch_t != WC_PUF_BCH_T || diag_log.ncw != WC_PUF_NUM_CODEWORDS) {
        /* First run, or a log from a different build: start over and take
         * this boot's reading as the reference everything is compared to.
         */
        memset(&diag_log, 0, sizeof(diag_log));
        diag_log.magic = DIAG_MAGIC;
        diag_log.bch_t = WC_PUF_BCH_T;
        diag_log.ncw = WC_PUF_NUM_CODEWORDS;
        diag_log.raw_bytes = WC_PUF_RAW_BYTES;
        memcpy(diag_log.reference, puf_raw, WC_PUF_RAW_BYTES);
        first = true;
        memset(&rec, 0, sizeof(rec));
    } else {
        memset(&rec, 0, sizeof(rec));
        for (i = 0; i < WC_PUF_RAW_BYTES; i++)
            dist += popcount8((uint8_t)(puf_raw[i] ^ diag_log.reference[i]));
        for (i = 0; i < WC_PUF_NUM_CODEWORDS; i++) {
            uint32_t d = codeword_distance(puf_raw, diag_log.reference, (int)i);
            rec.cw[i] = (uint8_t)d;
            if (d > max_cw)
                max_cw = d;
            if (d > (uint32_t)WC_PUF_BCH_T)
                over_t++;
        }
    }

    /* ---- end-to-end check against the real checkpoint, if enrolled ---- */
    if (cp->magic == PUF_MAGIC_PROVISIONAL)
        rec.cp_state = 1;
    else if (cp->magic == PUF_MAGIC_COMMITTED)
        rec.cp_state = 2;

    if (rec.cp_state != 0 && wc_PufInit(&ctx) == 0 &&
        wc_PufReadSram(&ctx, puf_raw, sizeof(puf_raw)) == 0) {
        rec.recon_ok = (wc_PufReconstructEx(&ctx, cp->helper,
                                            WC_PUF_HELPER_BYTES,
                                            cp->profileId) == 0) ? 1 : 0;
        wc_PufZeroize(&ctx);
    }

    /* ---- append and persist ---- */
    if (diag_log.count < DIAG_MAX_REC) {
        rec.seq = diag_log.count;
        rec.weight = (uint16_t)weight;
        rec.dist = (uint16_t)dist;
        rec.max_cw = (uint16_t)max_cw;
        rec.over_t = (uint16_t)over_t;
        diag_log.rec[diag_log.count] = rec;
        diag_log.count++;
        diag_log_save();
    } else {
        indicator_set(0x30, 0x30, 0x30);
        while (1) { tight_loop_contents(); }
    }

    /* ---- also print, in case a UART adapter is attached to GP0/GP1 ---- */
    wc_PufGetParams(&m, &n, &k, &t, &ncw);
    printf("\n=== fidelio SRAM PUF diagnostic, run %u ===\n", diag_log.count - 1);
    printf("profile  : BCH(%d,%d,t=%d) over GF(2^%d), %d codewords\n",
           n, k, t, m, ncw);
    printf("profileId: app %08lx / lib %08lx%s\n",
           (unsigned long)WC_PUF_PROFILE_ID,
           (unsigned long)wc_PufGetProfileId(),
           (wc_PufGetProfileId() == (word32)WC_PUF_PROFILE_ID) ? "" : "  MISMATCH");
    printf("region   : %p .. %p (%u bytes needed)\n",
           (void *)__puf_sram_start__, (void *)__puf_sram_end__,
           (unsigned)WC_PUF_RAW_BYTES);
    printf("weight   : %lu/%u bits (%lu%%)\n", (unsigned long)weight,
           (unsigned)WC_PUF_RAW_BITS,
           (unsigned long)(weight * 100u / WC_PUF_RAW_BITS));
    if (first) {
        printf("reference captured; power-cycle to start measuring drift\n");
    } else {
        printf("drift    : %lu/%u bits (%lu.%02lu%% BER)\n", (unsigned long)dist,
               (unsigned)WC_PUF_RAW_BITS,
               (unsigned long)(dist * 100u / WC_PUF_RAW_BITS),
               (unsigned long)((dist * 10000u / WC_PUF_RAW_BITS) % 100u));
        printf("worst codeword: %lu errors (t=%d), %lu codewords over t\n",
               (unsigned long)max_cw, t, (unsigned long)over_t);
    }
    printf("checkpoint magic %08lx, reconstruct %s\n",
           (unsigned long)cp->magic, rec.recon_ok ? "OK" : "n/a or FAILED");

    diag_verdict(max_cw, first);
}

#endif /* FIDELIO_PUF_DIAG */

int puf_provision(void)
{
    const struct puf_checkpoint *cp = (const struct puf_checkpoint *)FLASH_PUF_ADDR;
    wc_PufCtx ctx;
    uint32_t magic;
    int ret;

#ifdef FIDELIO_PUF_DIAG
    puf_diag_report(); /* does not return */
#endif

    /* The library and this translation unit must agree on the PUF profile.
     * WC_PUF_PROFILE_ID expands from the macros visible here, so a wolfSSL
     * built with different settings would size buffers differently.
     */
    if (wc_PufGetProfileId() != (word32)WC_PUF_PROFILE_ID)
        puf_halt(PUF_CODE_CONFIG, 0x20, 0, 0);

    /* If anything else has been placed over the response region it was
     * overwritten before we ever read it. Refuse rather than derive a wrong
     * secret from whatever is there now.
     */
    if ((uint32_t)(__puf_sram_end__ - __puf_sram_start__) < WC_PUF_RAW_BYTES ||
        __scratch_x_start__ < __puf_sram_end__ ||
        __StackOneBottom < __puf_sram_end__)
        puf_halt(PUF_CODE_CONFIG, 0x20, 0, 0);

    puf_sram_snapshot();

    if (wc_PufInit(&ctx) != 0)
        puf_halt(PUF_CODE_CONFIG, 0x20, 0, 0);
    if (wc_PufReadSram(&ctx, puf_raw, sizeof(puf_raw)) != 0)
        puf_halt(PUF_CODE_CONFIG, 0x20, 0, 0);

    magic = cp->magic;

    if (magic == PUF_MAGIC_COMMITTED) {
        /* Normal boot. */
        uint8_t salt[PUF_SALT_SZ];
        memcpy(salt, cp->salt, sizeof(salt));

        if (wc_PufReconstructEx(&ctx, cp->helper, WC_PUF_HELPER_BYTES,
                                cp->profileId) != 0) {
            wc_PufZeroize(&ctx);
            /* Reconstruction failure is usually transient: this boot's SRAM
             * reading drifted further from the enrolled one than the code can
             * correct. The next power-on is an independent draw and will very
             * likely succeed, so ask for one rather than declaring the device
             * dead.
             *
             * Deliberately no automatic retry and no flash write here. A warm
             * reset would replay the identical SRAM contents and fail again
             * identically, and erasing this sector to record an attempt would
             * put the only copy of the helper data at risk for no benefit.
             * Re-enrolling would "fix" the boot by silently minting a
             * different master secret and invalidating every credential, so
             * that is never done automatically either.
             */
            puf_halt(PUF_CODE_RECONSTRUCT, 0x20, 0, 0);
        }
        ret = puf_derive(&ctx, salt);
        wc_PufZeroize(&ctx);
        if (ret != 0)
            puf_halt(PUF_CODE_CONFIG, 0x20, 0, 0);
        return 0;
    }

    if (magic == PUF_MAGIC_PROVISIONAL) {
        /* Verification boot: prove the helper data written last time actually
         * reproduces the enrolled bits on a cold start before trusting it.
         * The salt is carried over unchanged, so the secret proven here is
         * the one the device will keep using.
         */
        if (wc_PufReconstructEx(&ctx, cp->helper, WC_PUF_HELPER_BYTES,
                                cp->profileId) == 0) {
            uint8_t salt[PUF_SALT_SZ];
            uint8_t helper[WC_PUF_HELPER_BYTES];
            memcpy(salt, cp->salt, sizeof(salt));
            memcpy(helper, cp->helper, sizeof(helper));
            puf_write_checkpoint(PUF_MAGIC_COMMITTED, salt, helper);
            ForceZero(helper, sizeof(helper));
            ret = puf_derive(&ctx, salt);
            wc_PufZeroize(&ctx);
            if (ret != 0)
                puf_halt(PUF_CODE_CONFIG, 0x20, 0, 0);
            return 0;
        }
        /* Verification failed. Nothing has been registered against this
         * device yet, so discarding the attempt and enrolling again costs
         * nothing -- and enrolling from this boot's reading may well land on
         * a more representative response than the last one did.
         */
        puf_factory_erase();
    }

    /* First boot, or a discarded verification attempt: enroll. */
    {
        uint8_t salt[PUF_SALT_SZ];
        uint8_t helper[WC_PUF_HELPER_BYTES];

        if (puf_make_salt(salt) != 0) {
            wc_PufZeroize(&ctx);
            puf_halt(PUF_CODE_CONFIG, 0x20, 0, 0);
        }
        if (wc_PufEnroll(&ctx) != 0) {
            wc_PufZeroize(&ctx);
            puf_halt(PUF_CODE_CONFIG, 0x20, 0, 0);
        }
        if (wc_PufGetHelperData(&ctx, helper, sizeof(helper)) != 0) {
            wc_PufZeroize(&ctx);
            puf_halt(PUF_CODE_CONFIG, 0x20, 0, 0);
        }
        puf_write_checkpoint(PUF_MAGIC_PROVISIONAL, salt, helper);
        ForceZero(helper, sizeof(helper));
        wc_PufZeroize(&ctx);
    }

    /* A watchdog reboot would not do: SRAM keeps its contents across a warm
     * reset, so the response would be replayed rather than re-measured and
     * the check would prove nothing. Ask for a real power cycle.
     */
    puf_halt(PUF_CODE_ENROLLED, 0x20, 0x20, 0);
    return -1;
}
