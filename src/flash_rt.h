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

/* Flash mutation, safe to call while executing from flash.
 *
 * The firmware runs from flash over XIP, so the moment an erase or program
 * starts the whole address space it is executing from disappears. Anything
 * that touches flash must therefore already be resident in RAM, and no
 * interrupt may fire into flash-resident code while the operation is in
 * flight. Both are handled here, once, rather than at every call site.
 *
 * These also relieve callers of the page-size rule: flash_range_program()
 * requires a multiple of FLASH_PAGE_SIZE, which several of Fidelio's
 * structures are not.
 */

#ifndef FLASH_RT_H
#define FLASH_RT_H

#include <stdint.h>
#include <stddef.h>

/* Erase whole sectors. off and len must be sector-aligned. */
void fidelio_flash_erase(uint32_t off, uint32_t len);

/* Program len bytes at off. len need not be a page multiple; the tail of the
 * final page is padded with 0xFF. The target must already be erased.
 */
void fidelio_flash_program(uint32_t off, const void *data, uint32_t len);

#endif /* FLASH_RT_H */
