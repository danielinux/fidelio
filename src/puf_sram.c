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

/* Bring-up diagnostic. Reconstruction fails if any single 127-bit codeword
 * carries more than WC_PUF_BCH_T flipped bits, and the margin shrinks at
 * temperature extremes and varies between chips, so a board should be
 * qualified before any credential is registered against it.
 *
 * Build with -DFIDELIO_PUF_DIAG=ON, run over a dozen or more power cycles
 * across the temperature range the key will see, and confirm reconstruction
 * succeeds every time.
 */
void puf_diag_report(void)
{
    const struct puf_checkpoint *cp = (const struct puf_checkpoint *)FLASH_PUF_ADDR;
    wc_PufCtx ctx;
    int m, n, k, t, ncw;
    uint32_t i;

    stdio_init_all();
    sleep_ms(3000); /* let the host attach to the UART */

    puf_sram_snapshot();

    wc_PufGetParams(&m, &n, &k, &t, &ncw);
    printf("\n=== fidelio SRAM PUF diagnostic ===\n");
    printf("profile  : BCH(%d,%d,t=%d) over GF(2^%d), %d codewords\n",
           n, k, t, m, ncw);
    printf("profileId: app %08lx / lib %08lx%s\n",
           (unsigned long)WC_PUF_PROFILE_ID,
           (unsigned long)wc_PufGetProfileId(),
           (wc_PufGetProfileId() == (word32)WC_PUF_PROFILE_ID) ? "" : "  MISMATCH");
    printf("region   : %p .. %p (%u bytes needed)\n",
           (void *)__puf_sram_start__, (void *)__puf_sram_end__,
           (unsigned)WC_PUF_RAW_BYTES);
    printf("checkpoint magic %08lx profileId %08lx\n",
           (unsigned long)cp->magic, (unsigned long)cp->profileId);

    printf("raw response:\n");
    for (i = 0; i < WC_PUF_RAW_BYTES; i++) {
        printf("%02x", puf_raw[i]);
        if ((i % 32) == 31)
            printf("\n");
    }

    /* Hamming weight is a coarse health check: a healthy SRAM PUF sits near
     * 50%. A response that is nearly all zeros or all ones means the region
     * was initialised by something and carries no entropy.
     */
    {
        uint32_t ones = 0;
        for (i = 0; i < WC_PUF_RAW_BYTES; i++) {
            uint8_t v = puf_raw[i];
            while (v) { ones += (v & 1u); v >>= 1; }
        }
        printf("hamming weight: %lu/%u bits (%lu%%)\n", (unsigned long)ones,
               (unsigned)WC_PUF_RAW_BITS,
               (unsigned long)(ones * 100u / WC_PUF_RAW_BITS));
    }

    if (cp->magic != PUF_MAGIC_COMMITTED && cp->magic != PUF_MAGIC_PROVISIONAL) {
        printf("no enrollment yet: boot once without FIDELIO_PUF_DIAG to enroll,\n"
               "then power-cycle and re-run this to measure drift.\n");
        while (1) { tight_loop_contents(); }
    }

    if (wc_PufInit(&ctx) != 0 ||
        wc_PufReadSram(&ctx, puf_raw, sizeof(puf_raw)) != 0) {
        printf("puf init failed\n");
        while (1) { tight_loop_contents(); }
    }

    if (wc_PufReconstructEx(&ctx, cp->helper, WC_PUF_HELPER_BYTES,
                            cp->profileId) != 0) {
        printf("RECONSTRUCT FAILED: at least one codeword exceeded t=%d.\n"
               "Normal firmware would ask for a power cycle and retry.\n"
               "If this repeats, the board is too noisy for this profile.\n", t);
    } else {
        uint8_t id[WC_PUF_ID_SZ];
        printf("reconstruct OK\n");
        if (wc_PufGetIdentity(&ctx, id, sizeof(id)) == 0) {
            printf("identity: ");
            for (i = 0; i < WC_PUF_ID_SZ; i++)
                printf("%02x", id[i]);
            printf("\n(identical on every boot of the same device)\n");
        }
    }
    wc_PufZeroize(&ctx);

    while (1) { tight_loop_contents(); }
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
