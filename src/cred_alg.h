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

/* Credential signature algorithms.
 *
 * Every credential key, whatever its algorithm, is derived from the device
 * master secret with HKDF-SHA256 over (algorithm, rpIdHash, nonce). Nothing
 * is stored per credential, so supporting more algorithms costs code and
 * time but never state.
 *
 * Measured derive+sign on RP2040 at 125 MHz, worst of 12 iterations
 * (doc/benchmark-rp2040-125mhz.txt):
 *
 *      Ed25519      83 ms      ML-DSA-44   346 ms
 *      ES256       116 ms      ML-DSA-65   366 ms
 *      ES384       556 ms      ML-DSA-87   513 ms
 *
 * ML-DSA signing is rejection-sampled, so its cost varies by up to 4x between
 * runs; the figures above are worst case, not means.
 */

#ifndef CRED_ALG_H
#define CRED_ALG_H

#include <stdint.h>
#include <stdbool.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/random.h"
#ifdef HAVE_ED25519
#include "wolfssl/wolfcrypt/ed25519.h"
#endif
#ifdef WOLFSSL_HAVE_MLDSA
#include "wolfssl/wolfcrypt/wc_mldsa.h"
#endif
#include "wolfcose/wolfcose.h"

/* Compact identifiers, stored in the credential ID and covered by its MAC.
 * These are wire format: never renumber them.
 */
#define CRED_ALG_ES256      1
#define CRED_ALG_ED25519    2
#define CRED_ALG_ES384      3
#define CRED_ALG_ES512      4
#define CRED_ALG_MLDSA44    5
#define CRED_ALG_MLDSA65    6
#define CRED_ALG_MLDSA87    7

/* Largest public key and signature across the enabled set, used to size the
 * CTAP2 response buffers. ML-DSA-87: 2592-byte key, 4627-byte signature.
 */
#ifdef WOLFSSL_HAVE_MLDSA
#define CRED_PUB_MAX   2592
#define CRED_SIG_MAX   4627
#else
#define CRED_PUB_MAX   133
#define CRED_SIG_MAX   139
#endif

struct cred_alg {
    uint8_t id;         /* CRED_ALG_*, as stored in the credential ID */
    int32_t cose;       /* COSE algorithm identifier */
    int32_t cose_alt;   /* fully-specified alias (RFC 9864), 0 if none */
    uint8_t rank;       /* selection preference; higher is stronger */
    uint16_t priv_len;  /* private scalar / seed length in bytes */
    uint16_t sig_max;   /* upper bound on signature size */
};

/* A derived, ready-to-use credential key. Opaque to callers apart from ->alg.
 * ML-DSA keys are ~7.9 KB and live in a single static slot, so at most one
 * credential key may be live at a time.
 */
struct cred_key {
    const struct cred_alg *alg;
    bool live;
    union {
        ecc_key ecc;
#ifdef HAVE_ED25519
        ed25519_key ed;
#endif
    } k;
#ifdef WOLFSSL_HAVE_MLDSA
    wc_MlDsaKey *mldsa;
#endif
};

/* Lookup. cose may be either the primary or the fully-specified alias. */
const struct cred_alg *cred_alg_by_cose(int32_t cose);
const struct cred_alg *cred_alg_by_id(uint8_t id);

/* Highest-ranked algorithm present in `mask`, a bitmap of (1u << id).
 * Returns NULL if the mask names nothing supported.
 */
const struct cred_alg *cred_alg_best(uint32_t mask);

/* Iterate the supported set, for authenticatorGetInfo. */
const struct cred_alg *cred_alg_at(unsigned idx);

/* Derive the credential key for (alg, rpIdHash, nonce) from the master
 * secret. Deterministic: the same inputs always reproduce the same key.
 */
int cred_alg_derive(const struct cred_alg *alg, const uint8_t *secret,
                    const uint8_t *rpIdHash, const uint8_t *nonce,
                    struct cred_key *out);

/* Append the public key as a COSE_Key map at the context's cursor. */
int cred_alg_pubkey_cose(struct cred_key *key, WOLFCOSE_CBOR_CTX *c);

/* Sign a WebAuthn message (authData || clientDataHash). Each algorithm
 * applies its own hashing: ECDSA pre-hashes with the matching SHA-2, EdDSA
 * and ML-DSA sign the message directly.
 */
int cred_alg_sign(struct cred_key *key, const uint8_t *msg, uint16_t msg_len,
                  uint8_t *sig, uint16_t *sig_len, WC_RNG *rng);

void cred_key_free(struct cred_key *key);

#endif /* CRED_ALG_H */
