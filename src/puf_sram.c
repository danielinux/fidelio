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

/* The reserved SRAM response. Placed by src/puf_sram.ld at the base of
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

struct puf_checkpoint {
    uint32_t magic;
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

/* Blink forever. The stock Pico has a single LED, so the pattern rather than
 * the colour is what distinguishes the halt states. The caller has already
 * run indicator_init(); re-running it would add a second copy of the WS2812
 * PIO program on RGB boards.
 */
static void puf_halt_blinking(uint32_t on_ms, uint32_t off_ms,
                              uint16_t r, uint16_t g, uint16_t b)
{
    while (1) {
        indicator_set(r, g, b);
        sleep_ms(on_ms);
        indicator_set_idle();
        sleep_ms(off_ms);
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

/* Bring-up diagnostic. BCH(127,64,t=10) corrects at most 10 flipped bits per
 * 127-bit codeword. Typical SRAM PUF bit error rates leave usable but not
 * generous margin, and the margin shrinks at temperature extremes, so a board
 * should be qualified before any credential is registered against it.
 *
 * Build with -DFIDELIO_PUF_DIAG, run over ~20 power cycles across the
 * temperature range the key will see, and watch the worst-case column. A
 * board whose worst codeword approaches 10 is not a safe PUF host.
 */
void puf_diag_report(void)
{
    const struct puf_checkpoint *cp = (const struct puf_checkpoint *)FLASH_PUF_ADDR;
    wc_PufCtx ctx;
    uint32_t i;

    stdio_init_all();
    sleep_ms(3000); /* let the host attach to the CDC port */

    puf_sram_snapshot();

    printf("\n=== fidelio SRAM PUF diagnostic ===\n");
    printf("region   : %p .. %p\n", (void *)__puf_sram_start__,
           (void *)__puf_sram_end__);
    printf("checkpoint magic: %08lx\n", (unsigned long)cp->magic);

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
               WC_PUF_RAW_BITS, (unsigned long)(ones * 100u / WC_PUF_RAW_BITS));
    }

    if (cp->magic != PUF_MAGIC_COMMITTED && cp->magic != PUF_MAGIC_PROVISIONAL) {
        printf("no enrollment yet: boot once without FIDELIO_PUF_DIAG to enroll,\n"
               "then power-cycle and re-run this to measure drift.\n");
        while (1) { tight_loop_contents(); }
    }

    /* Per-codeword error count against the enrolled bits. This is the number
     * BCH has to correct on this boot; t = 10 is the ceiling.
     */
    if (wc_PufInit(&ctx) != 0 ||
        wc_PufReadSram(&ctx, puf_raw, sizeof(puf_raw)) != 0) {
        printf("puf init failed\n");
        while (1) { tight_loop_contents(); }
    }

    if (wc_PufReconstruct(&ctx, cp->helper, WC_PUF_HELPER_BYTES) != 0) {
        printf("RECONSTRUCT FAILED: at least one codeword exceeded t=10.\n"
               "This board would refuse to boot in normal firmware.\n");
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
#ifdef FIDELIO_PUF_DIAG
    puf_diag_report(); /* does not return */
#endif
    const struct puf_checkpoint *cp = (const struct puf_checkpoint *)FLASH_PUF_ADDR;
    wc_PufCtx ctx;
    uint32_t magic;
    int ret;

    /* If anything else has been placed over the response region it was
     * overwritten before we ever read it. Refuse rather than derive a wrong
     * secret from whatever is there now.
     */
    if ((uint32_t)(__puf_sram_end__ - __puf_sram_start__) < WC_PUF_RAW_BYTES ||
        __scratch_x_start__ < __puf_sram_end__ ||
        __StackOneBottom < __puf_sram_end__)
        puf_halt_blinking(100, 100, 0x20, 0, 0);

    puf_sram_snapshot();

    if (wc_PufInit(&ctx) != 0)
        puf_halt_blinking(100, 100, 0x20, 0, 0);
    if (wc_PufReadSram(&ctx, puf_raw, sizeof(puf_raw)) != 0)
        puf_halt_blinking(100, 100, 0x20, 0, 0);

    magic = cp->magic;

    if (magic == PUF_MAGIC_COMMITTED) {
        /* Normal boot. A failure here means the response drifted beyond what
         * BCH(127,64,t=10) can correct. Re-enrolling would silently mint a
         * different master secret and destroy every registered credential,
         * so stop instead.
         */
        uint8_t salt[PUF_SALT_SZ];
        memcpy(salt, cp->salt, sizeof(salt));
        if (wc_PufReconstruct(&ctx, cp->helper, WC_PUF_HELPER_BYTES) != 0) {
            wc_PufZeroize(&ctx);
            puf_halt_blinking(100, 100, 0x20, 0, 0);
        }
        ret = puf_derive(&ctx, salt);
        wc_PufZeroize(&ctx);
        if (ret != 0)
            puf_halt_blinking(100, 100, 0x20, 0, 0);
        return 0;
    }

    if (magic == PUF_MAGIC_PROVISIONAL) {
        /* Verification boot: prove the helper data written last time actually
         * reproduces the enrolled bits on a cold start before trusting it.
         * The salt is carried over unchanged, so the secret proven here is
         * the one the device will keep using.
         */
        if (wc_PufReconstruct(&ctx, cp->helper, WC_PUF_HELPER_BYTES) == 0) {
            uint8_t salt[PUF_SALT_SZ];
            uint8_t helper[WC_PUF_HELPER_BYTES];
            memcpy(salt, cp->salt, sizeof(salt));
            memcpy(helper, cp->helper, sizeof(helper));
            puf_write_checkpoint(PUF_MAGIC_COMMITTED, salt, helper);
            ForceZero(helper, sizeof(helper));
            ret = puf_derive(&ctx, salt);
            ForceZero(salt, sizeof(salt));
            wc_PufZeroize(&ctx);
            if (ret != 0)
                puf_halt_blinking(100, 100, 0x20, 0, 0);
            return 0;
        }
        /* Verification failed. Nothing has been registered against this
         * device yet, so discarding the attempt and enrolling again costs
         * nothing.
         */
        puf_factory_erase();
    }

    /* First boot, or a discarded verification attempt: enroll. */
    {
        uint8_t salt[PUF_SALT_SZ];
        if (puf_make_salt(salt) != 0) {
            wc_PufZeroize(&ctx);
            puf_halt_blinking(100, 100, 0x20, 0, 0);
        }
        if (wc_PufEnroll(&ctx) != 0) {
            wc_PufZeroize(&ctx);
            puf_halt_blinking(100, 100, 0x20, 0, 0);
        }
        puf_write_checkpoint(PUF_MAGIC_PROVISIONAL, salt, ctx.helperData);
        ForceZero(salt, sizeof(salt));
        wc_PufZeroize(&ctx);
    }

    /* A watchdog reboot would not do: SRAM keeps its contents across a warm
     * reset, so the response would be replayed rather than re-measured and
     * the check would prove nothing. Ask for a real power cycle.
     */
    puf_halt_blinking(700, 300, 0x20, 0x20, 0);
    return -1;
}
