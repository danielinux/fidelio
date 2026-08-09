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

/* SRAM PUF root of trust.
 *
 * The device master secret is not stored. It is reconstructed at every boot
 * from the power-on state of a reserved block of SRAM, using the wolfCrypt
 * BCH(127,64,t=10) fuzzy extractor. The only thing kept in flash is the
 * checkpoint: non-secret helper data plus a state magic.
 */

#ifndef PUF_SRAM_H
#define PUF_SRAM_H

#include <stdint.h>

/* Copy the power-on SRAM response out of the reserved region. Must be the
 * first thing main() does, before clocks, GPIO or any other subsystem.
 */
void puf_sram_snapshot(void);

/* Run the enroll / verify / reconstruct state machine and derive the master
 * secret. Returns 0 when the secret is available. Does not return in the
 * states that need operator action (first-boot enrollment) or that are
 * unrecoverable (reconstruction failure).
 */
int puf_provision(void);

/* The 32-byte master secret. Valid only after puf_provision() returned 0. */
const uint8_t *puf_master_secret(void);

/* Draw a fresh salt and re-derive the master secret in place, keeping the
 * enrolled helper data. Every credential ever derived becomes unreachable,
 * because they all hang off the master secret -- but the PUF stays enrolled,
 * so no re-enrollment power cycle is needed. This is what makes an
 * authenticatorReset actually invalidate credentials.
 */
int puf_rotate_salt(void);

/* Erase the checkpoint. The next boot enrolls again, which yields a different
 * master secret and so invalidates every derived credential.
 */
void puf_factory_erase(void);

/* Raw power-on SRAM response, for use as an entropy source. This is the
 * unprocessed readout, not the extracted stable bits.
 */
const uint8_t *puf_raw_response(uint32_t *len);

#endif /* PUF_SRAM_H */
