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
#include "pico/stdlib.h"
#include "hardware/gpio.h"
#include "hardware/adc.h"
#include <string.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/misc.h"
#include "puf_sram.h"


#define IN3_PIN 29
#define IN0_PIN 28
#define IN1_PIN 27
#define IN2_PIN 26

const uint32_t IN[4] = {IN0_PIN, IN1_PIN, IN2_PIN, IN3_PIN};
static int adc_initialized = 0;

const int in_a[8] = { 0, 1, 2, 3, 1, 3, 0, 2 };

/* Collect sz bytes of raw ADC noise: eight 3-bit samples per 3 output bytes,
 * rotating across the four floating inputs.
 */
static void adc_noise(unsigned char *output, unsigned int sz)
{
    uint32_t i;
    uint32_t result = 0;
    uint32_t rd = 0, wsz;

    if (!adc_initialized) {
        adc_init();
        for (i = 0; i < 4; i++) {
            adc_gpio_init(IN[i]);
        }
        adc_initialized = 1;
        sleep_ms(10);
    }

    /* Perform eight 3-bit samples with sources 0-1-2-4 */
    for (i = 0; rd < sz; i = (i + 1) % 8) {
        adc_select_input(in_a[i]);

        /* Read the least significant 3 bits from the ADC */
        result = (result << 3) | (adc_read() & 0x00000007);

        /* Introduce a delay to capture environmental noise */
        sleep_ms(1);

        /* If we've completed eight samples, copy the result to the output */
        if (i == 7) {
            wsz = 3;
            if (wsz > (sz - rd)) {
                wsz = sz - rd;
            }

            memcpy(output + rd, &result, wsz);
            rd += wsz;
            result = 0;
        }
    }
}

/* Seed material for the wolfCrypt DRBG.
 *
 * Two independent sources are conditioned together with SHA-256:
 *
 *  - the power-on SRAM readout, which carries a large amount of startup
 *    entropy but is fixed for the lifetime of a power cycle;
 *  - ADC noise from the floating inputs, which is weak per sample but does
 *    vary from call to call.
 *
 * Hashing both means the result is no worse than the stronger of the two, and
 * keeping the ADC in the mix preserves per-call variation that the SRAM
 * readout alone cannot provide. A counter is folded in so successive blocks
 * of a single request differ.
 */
int custom_random_seed(unsigned char *output, unsigned int sz)
{
    const uint8_t *sram;
    uint32_t sram_len = 0;
    /* Each ADC byte costs ~2.7 ms of sampling delay, and this runs on every
     * wc_InitRng(). 16 bytes per 32-byte output block keeps a full DRBG seed
     * request faster than the previous ADC-only implementation while adding
     * the SRAM entropy on top.
     */
    unsigned char noise[16];
    unsigned char block[WC_SHA256_DIGEST_SIZE];
    uint32_t counter = 0;
    unsigned int rd = 0;

    sram = puf_raw_response(&sram_len);

    while (rd < sz) {
        wc_Sha256 sha;
        unsigned int chunk = sz - rd;

        adc_noise(noise, sizeof(noise));

        if (wc_InitSha256(&sha) != 0)
            return -1;
        wc_Sha256Update(&sha, (const byte *)&counter, sizeof(counter));
        wc_Sha256Update(&sha, sram, sram_len);
        wc_Sha256Update(&sha, noise, sizeof(noise));
        wc_Sha256Final(&sha, block);
        wc_Sha256Free(&sha);

        if (chunk > sizeof(block))
            chunk = sizeof(block);
        memcpy(output + rd, block, chunk);
        rd += chunk;
        counter++;
    }

    ForceZero(noise, sizeof(noise));
    ForceZero(block, sizeof(block));
    return 0;
}
