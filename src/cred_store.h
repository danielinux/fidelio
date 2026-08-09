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

/* Encrypted store for discoverable credentials (resident keys).
 *
 * Non-discoverable credentials need no storage: the credential ID carries
 * everything required to re-derive the key. Discoverable ones do, because the
 * relying party sends no credential ID at all -- the authenticator must find
 * the credential from the rpId alone, and hand back the user handle.
 *
 * That record set is exactly what an attacker wants from a stolen key: which
 * services the owner has accounts with, and under what user IDs. Storing it in
 * the clear would give away by inspection what the SRAM PUF work exists to
 * protect, so the whole vault is sealed with ChaCha20-Poly1305 under a key
 * derived from the device master secret -- which is itself never stored and
 * only exists while the device is powered.
 */

#ifndef CRED_STORE_H
#define CRED_STORE_H

#include <stdint.h>
#include <stdbool.h>
#include "cred_alg.h"

#define CRED_STORE_SLOTS      16
#define CRED_STORE_USER_MAX   64
#define CRED_STORE_NAME_MAX   32

struct cred_record {
    uint8_t rp_id_hash[32];
    uint8_t cred_id[CRED_ID_LEN_MAX];
    uint8_t cred_id_len;
    uint8_t user_id[CRED_STORE_USER_MAX];
    uint8_t user_id_len;
    char    user_name[CRED_STORE_NAME_MAX + 1];
};

/* Load and decrypt the vault. Safe to call repeatedly; the first call after
 * boot does the work. Returns 0 if the vault is valid or absent (an absent
 * vault is an empty one), non-zero if it exists but fails authentication.
 */
int cred_store_load(void);

/* Add or replace the credential for (rp_id_hash, user_id). Re-encrypts and
 * persists the whole vault under a freshly derived key.
 */
int cred_store_put(const struct cred_record *rec);

/* Nth credential for this relying party, in slot order. Returns NULL when
 * there is no Nth one.
 */
const struct cred_record *cred_store_get(const uint8_t *rp_id_hash,
                                         unsigned index);

/* How many credentials this relying party has. */
unsigned cred_store_count(const uint8_t *rp_id_hash);

/* Erase the vault (factory reset). */
void cred_store_wipe(void);

#endif /* CRED_STORE_H */
