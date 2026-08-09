/* Fidelio
 *
 * (c) 2023 Daniele Lacamera <root@danielinux.net>
 *
 *
 * Fidelio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Fidelio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
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
#include "pins.h"

/* Which ADC channels are free to float on this board. Channels wired to
 * something else (the presence button, typically) are excluded by the board
 * definition in pins.h, because adc_gpio_init() would steal the pin from its
 * digital function.
 */
static const uint8_t adc_channels[] = FIDELIO_ADC_CHANNELS;

#define ADC_NUM_CHANNELS (sizeof(adc_channels) / sizeof(adc_channels[0]))

static int adc_initialized = 0;

/* Collect sz bytes of raw ADC noise: eight 3-bit samples per 3 output bytes,
 * rotating across the board's floating inputs.
 */
static void adc_noise(unsigned char *output, unsigned int sz)
{
    uint32_t i;
    uint32_t result = 0;
    uint32_t rd = 0, wsz;

    if (!adc_initialized) {
        adc_init();
        for (i = 0; i < ADC_NUM_CHANNELS; i++) {
            adc_gpio_init(FIDELIO_ADC_CHANNEL_GPIO(adc_channels[i]));
        }
        adc_initialized = 1;
        sleep_ms(10);
    }

    /* Eight 3-bit samples, round-robin across the available channels */
    for (i = 0; rd < sz; i = (i + 1) % 8) {
        adc_select_input(adc_channels[i % ADC_NUM_CHANNELS]);

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
