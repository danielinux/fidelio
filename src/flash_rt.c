/* Fidelio
 *
 * (c) 2023 Daniele Lacamera <root@danielinux.net>
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
 */

#include <string.h>
#include "pico/stdlib.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "flash_rt.h"

/* Both routines are __not_in_flash_func: they must already be in RAM before
 * the flash they would otherwise be fetched from goes away. Interrupts are
 * masked for the duration for the same reason -- the USB handler lives in
 * flash, and servicing it mid-erase would fetch from an unreadable XIP
 * window. The host simply sees a stall and retries.
 */

void __not_in_flash_func(fidelio_flash_erase)(uint32_t off, uint32_t len)
{
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(off, len);
    restore_interrupts(ints);
}

void __not_in_flash_func(fidelio_flash_program)(uint32_t off, const void *data,
                                                uint32_t len)
{
    const uint8_t *src = (const uint8_t *)data;
    uint8_t page[FLASH_PAGE_SIZE];
    uint32_t done = 0;

    while (done < len) {
        uint32_t chunk = len - done;
        uint32_t ints;

        if (chunk > FLASH_PAGE_SIZE)
            chunk = FLASH_PAGE_SIZE;

        /* Bounce through a RAM page so a partial tail is padded rather than
         * handed to flash_range_program(), which requires a page multiple.
         * The source may also be in flash (copy-forward of an existing
         * page), which must be read before the write window opens.
         */
        memset(page, 0xFF, sizeof(page));
        memcpy(page, src + done, chunk);

        ints = save_and_disable_interrupts();
        flash_range_program(off + done, page, FLASH_PAGE_SIZE);
        restore_interrupts(ints);

        done += chunk;
    }
}
