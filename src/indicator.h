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
#ifndef INDICATOR_H
#define INDICATOR_H

#include <stdbool.h>
#include <stdint.h>

void indicator_init(void);
void indicator_set_idle(void);
void indicator_set(uint16_t r, uint16_t g, uint16_t b);
/* Wait for the presence button, bounded. Returns true if it was pressed,
 * false on timeout. An unbounded wait lets any USB host wedge the
 * authenticator indefinitely by starting an operation and never touching the
 * button, since CTAPHID offers no way to cancel it here.
 */
#define PRESENCE_TIMEOUT_MS 30000
bool indicator_wait_for_button(uint16_t r, uint16_t g, uint16_t b);

#endif
