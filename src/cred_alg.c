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

#include <string.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/kdf.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/sha512.h"
#include "cred_alg.h"

extern void ForceZero(void* mem, word32 len);

#define HASH_SZ  32
#define NONCE_SZ 32

/* COSE identifiers. Primary first, then the RFC 9864 fully-specified alias
 * where one exists; a relying party may name either.
 */
#define COSE_ES256    (-7)
#define COSE_ESP256   (-9)
#define COSE_EDDSA    (-8)
#define COSE_ED25519  (-19)
#define COSE_ES384    (-35)
#define COSE_ESP384   (-51)
#define COSE_ES512    (-36)
#define COSE_ESP512   (-52)
#define COSE_MLDSA44  (-48)
#define COSE_MLDSA65  (-49)
#define COSE_MLDSA87  (-50)

/* Ranked weakest to strongest. cred_alg_best() picks the highest rank the
 * relying party is willing to accept.
 */
static const struct cred_alg alg_table[] = {
#ifdef HAVE_ECC256
    { CRED_ALG_ES256,   COSE_ES256,   COSE_ESP256, 10, 32, 80 },
#endif
#ifdef HAVE_ED25519
    { CRED_ALG_ED25519, COSE_EDDSA,   COSE_ED25519, 20, 32, 64 },
#endif
#ifdef HAVE_ECC384
    { CRED_ALG_ES384,   COSE_ES384,   COSE_ESP384, 30, 48, 112 },
#endif
#ifdef HAVE_ECC521
    { CRED_ALG_ES512,   COSE_ES512,   COSE_ESP512, 40, 66, 145 },
#endif
#ifdef WOLFSSL_HAVE_MLDSA
    { CRED_ALG_MLDSA44, COSE_MLDSA44, 0, 50, 32, WC_MLDSA_44_SIG_SIZE },
    { CRED_ALG_MLDSA65, COSE_MLDSA65, 0, 60, 32, WC_MLDSA_65_SIG_SIZE },
    { CRED_ALG_MLDSA87, COSE_MLDSA87, 0, 70, 32, WC_MLDSA_87_SIG_SIZE },
#endif
};

#define ALG_COUNT (sizeof(alg_table) / sizeof(alg_table[0]))

#ifdef WOLFSSL_HAVE_MLDSA
/* One instance, ~7.9 KB. The 2 KB core-0 stack cannot hold it and CTAP2
 * only ever has one credential key in flight.
 */
static wc_MlDsaKey mldsa_slot;
#endif

const struct cred_alg *cred_alg_at(unsigned idx)
{
    if (idx >= ALG_COUNT)
        return NULL;
    return &alg_table[idx];
}

const struct cred_alg *cred_alg_by_cose(int32_t cose)
{
    unsigned i;
    for (i = 0; i < ALG_COUNT; i++) {
        if (alg_table[i].cose == cose ||
            (alg_table[i].cose_alt != 0 && alg_table[i].cose_alt == cose))
            return &alg_table[i];
    }
    return NULL;
}

const struct cred_alg *cred_alg_by_id(uint8_t id)
{
    unsigned i;
    for (i = 0; i < ALG_COUNT; i++) {
        if (alg_table[i].id == id)
            return &alg_table[i];
    }
    return NULL;
}

const struct cred_alg *cred_alg_best(uint32_t mask)
{
    const struct cred_alg *best = NULL;
    unsigned i;
    for (i = 0; i < ALG_COUNT; i++) {
        if ((mask & (1u << alg_table[i].id)) == 0)
            continue;
        if (best == NULL || alg_table[i].rank > best->rank)
            best = &alg_table[i];
    }
    return best;
}

/* Expand the master secret into `len` bytes bound to this credential.
 * `counter` lets the ECDSA path retry when a derived scalar happens to fall
 * outside [1, n-1].
 */
static int derive_bytes(const struct cred_alg *alg, const uint8_t *secret,
                        const uint8_t *rpIdHash, const uint8_t *nonce,
                        uint8_t counter, uint8_t *out, uint16_t len)
{
    uint8_t info[16 + HASH_SZ + NONCE_SZ + 2];
    uint16_t n = 0;
    int ret;

    memcpy(info, "fidelio-cred-v2", 15);
    n = 15;
    info[n++] = alg->id;
    memcpy(info + n, rpIdHash, HASH_SZ);
    n += HASH_SZ;
    memcpy(info + n, nonce, NONCE_SZ);
    n += NONCE_SZ;
    info[n++] = counter;

    ret = wc_HKDF_Expand(WC_SHA256, secret, HASH_SZ, info, n, out, len);
    ForceZero(info, sizeof(info));
    return ret;
}

#if defined(HAVE_ECC256) || defined(HAVE_ECC384) || defined(HAVE_ECC521)
static int ecc_curve_of(const struct cred_alg *alg, int *curveId, int *bits)
{
    switch (alg->id) {
#ifdef HAVE_ECC256
        case CRED_ALG_ES256: *curveId = ECC_SECP256R1; *bits = 256; return 0;
#endif
#ifdef HAVE_ECC384
        case CRED_ALG_ES384: *curveId = ECC_SECP384R1; *bits = 384; return 0;
#endif
#ifdef HAVE_ECC521
        case CRED_ALG_ES512: *curveId = ECC_SECP521R1; *bits = 521; return 0;
#endif
        default: return -1;
    }
}

static int derive_ecc(const struct cred_alg *alg, const uint8_t *secret,
                      const uint8_t *rpIdHash, const uint8_t *nonce,
                      struct cred_key *out)
{
    uint8_t priv[66];
    int curveId, bits, ret = -1;
    uint8_t attempt;

    if (ecc_curve_of(alg, &curveId, &bits) != 0)
        return -1;

    for (attempt = 0; attempt < 16; attempt++) {
        if (derive_bytes(alg, secret, rpIdHash, nonce, attempt,
                         priv, alg->priv_len) != 0)
            break;

        /* The order of P-521 is ~2^521 but the scalar occupies 66 bytes, so
         * most raw values exceed it. Mask down to the curve's bit length
         * before importing; the retry counter covers the remainder.
         */
        if ((bits % 8) != 0)
            priv[0] &= (uint8_t)((1u << (bits % 8)) - 1u);

        if (wc_ecc_init(&out->k.ecc) != 0)
            break;
        if (wc_ecc_import_private_key_ex(priv, alg->priv_len, NULL, 0,
                                         &out->k.ecc, curveId) == 0 &&
            wc_ecc_make_pub(&out->k.ecc, NULL) == 0) {
            ret = 0;
            break;
        }
        wc_ecc_free(&out->k.ecc);
    }

    ForceZero(priv, sizeof(priv));
    return ret;
}
#endif

int cred_alg_derive(const struct cred_alg *alg, const uint8_t *secret,
                    const uint8_t *rpIdHash, const uint8_t *nonce,
                    struct cred_key *out)
{
    if (alg == NULL || secret == NULL || out == NULL)
        return -1;

    memset(out, 0, sizeof(*out));
    out->alg = alg;

    switch (alg->id) {
#if defined(HAVE_ECC256) || defined(HAVE_ECC384) || defined(HAVE_ECC521)
        case CRED_ALG_ES256:
        case CRED_ALG_ES384:
        case CRED_ALG_ES512:
            if (derive_ecc(alg, secret, rpIdHash, nonce, out) != 0)
                return -1;
            out->live = true;
            return 0;
#endif
#ifdef HAVE_ED25519
        case CRED_ALG_ED25519: {
            uint8_t seed[32];
            uint8_t pub[32];
            int ret = -1;
            if (derive_bytes(alg, secret, rpIdHash, nonce, 0, seed,
                             sizeof(seed)) == 0 &&
                wc_ed25519_init(&out->k.ed) == 0) {
                /* wc_ed25519_make_public() writes the derived public key into
                 * the caller's buffer and sets pubKeySet, but does NOT store
                 * it in key->p. Signing hashes the public key into the
                 * signature and the COSE_Key export reads key->p, so without
                 * importing it back both the published key and every
                 * signature would be silently wrong.
                 */
                if (wc_ed25519_import_private_only(seed, sizeof(seed),
                                                   &out->k.ed) == 0 &&
                    wc_ed25519_make_public(&out->k.ed, pub, sizeof(pub)) == 0 &&
                    wc_ed25519_import_public(pub, sizeof(pub),
                                             &out->k.ed) == 0) {
                    out->live = true;
                    ret = 0;
                } else {
                    wc_ed25519_free(&out->k.ed);
                }
            }
            ForceZero(seed, sizeof(seed));
            return ret;
        }
#endif
#ifdef WOLFSSL_HAVE_MLDSA
        case CRED_ALG_MLDSA44:
        case CRED_ALG_MLDSA65:
        case CRED_ALG_MLDSA87: {
            uint8_t seed[32];
            byte level;
            int ret = -1;

            if (alg->id == CRED_ALG_MLDSA44)
                level = WC_ML_DSA_44;
            else if (alg->id == CRED_ALG_MLDSA65)
                level = WC_ML_DSA_65;
            else
                level = WC_ML_DSA_87;

            if (derive_bytes(alg, secret, rpIdHash, nonce, 0, seed,
                             sizeof(seed)) == 0 &&
                wc_MlDsaKey_Init(&mldsa_slot, NULL, INVALID_DEVID) == 0) {
                if (wc_MlDsaKey_SetParams(&mldsa_slot, level) == 0 &&
                    wc_MlDsaKey_MakeKeyFromSeed(&mldsa_slot, seed) == 0) {
                    out->mldsa = &mldsa_slot;
                    out->live = true;
                    ret = 0;
                } else {
                    wc_MlDsaKey_Free(&mldsa_slot);
                }
            }
            ForceZero(seed, sizeof(seed));
            return ret;
        }
#endif
        default:
            return -1;
    }
}

int cred_alg_pubkey_cose(struct cred_key *key, WOLFCOSE_CBOR_CTX *c)
{
    WOLFCOSE_KEY ck;
    size_t written = 0;

    if (key == NULL || !key->live || c == NULL)
        return -1;
    if (wc_CoseKey_Init(&ck) != WOLFCOSE_SUCCESS)
        return -1;

    switch (key->alg->id) {
#if defined(HAVE_ECC256) || defined(HAVE_ECC384) || defined(HAVE_ECC521)
        case CRED_ALG_ES256:
        case CRED_ALG_ES384:
        case CRED_ALG_ES512: {
            int32_t crv;
            if (key->alg->id == CRED_ALG_ES256)
                crv = WOLFCOSE_CRV_P256;
            else if (key->alg->id == CRED_ALG_ES384)
                crv = WOLFCOSE_CRV_P384;
            else
                crv = WOLFCOSE_CRV_P521;
            if (wc_CoseKey_SetEcc(&ck, crv, &key->k.ecc) != WOLFCOSE_SUCCESS)
                return -1;
            break;
        }
#endif
#ifdef HAVE_ED25519
        case CRED_ALG_ED25519:
            if (wc_CoseKey_SetEd25519(&ck, &key->k.ed) != WOLFCOSE_SUCCESS)
                return -1;
            break;
#endif
#ifdef WOLFSSL_HAVE_MLDSA
        case CRED_ALG_MLDSA44:
        case CRED_ALG_MLDSA65:
        case CRED_ALG_MLDSA87:
            if (wc_CoseKey_SetMlDsa(&ck, key->alg->cose,
                                    key->mldsa) != WOLFCOSE_SUCCESS)
                return -1;
            break;
#endif
        default:
            return -1;
    }

    ck.alg = key->alg->cose;
    /* Every key here still holds its private half; wc_CoseKey_Set*() records
     * that and wc_CoseKey_Encode() would serialise it into a reply that goes
     * out over USB. This is a public-key-only serialiser by contract.
     */
    ck.hasPrivate = 0;

    if (wc_CoseKey_Encode(&ck, c->buf + c->idx, c->bufSz - c->idx,
                          &written) != WOLFCOSE_SUCCESS)
        return -1;
    c->idx += written;
    return 0;
}

int cred_alg_sign(struct cred_key *key, const uint8_t *msg, uint16_t msg_len,
                  uint8_t *sig, uint16_t *sig_len, WC_RNG *rng)
{
    word32 len;

    if (key == NULL || !key->live || msg == NULL || sig == NULL ||
        sig_len == NULL)
        return -1;
    len = *sig_len;

    switch (key->alg->id) {
#if defined(HAVE_ECC256) || defined(HAVE_ECC384) || defined(HAVE_ECC521)
        case CRED_ALG_ES256:
        case CRED_ALG_ES384:
        case CRED_ALG_ES512: {
            /* ECDSA pre-hashes with the SHA-2 variant the COSE algorithm
             * names: ES256/SHA-256, ES384/SHA-384, ES512/SHA-512.
             */
            uint8_t digest[64];
            uint16_t dlen;

            if (key->alg->id == CRED_ALG_ES256) {
                if (wc_Sha256Hash(msg, msg_len, digest) != 0) return -1;
                dlen = 32;
            } else if (key->alg->id == CRED_ALG_ES384) {
                if (wc_Sha384Hash(msg, msg_len, digest) != 0) return -1;
                dlen = 48;
            } else {
                if (wc_Sha512Hash(msg, msg_len, digest) != 0) return -1;
                dlen = 64;
            }
            if (wc_ecc_sign_hash(digest, dlen, sig, &len, rng,
                                 &key->k.ecc) != 0)
                return -1;
            break;
        }
#endif
#ifdef HAVE_ED25519
        case CRED_ALG_ED25519:
            /* EdDSA signs the message itself; no pre-hash. */
            if (wc_ed25519_sign_msg(msg, msg_len, sig, &len, &key->k.ed) != 0)
                return -1;
            break;
#endif
#ifdef WOLFSSL_HAVE_MLDSA
        case CRED_ALG_MLDSA44:
        case CRED_ALG_MLDSA65:
        case CRED_ALG_MLDSA87:
            /* FIPS 204 pure signing with an empty context, per RFC 9964. */
            if (wc_MlDsaKey_SignCtx(key->mldsa, NULL, 0, sig, &len,
                                    msg, msg_len, rng) != 0)
                return -1;
            break;
#endif
        default:
            return -1;
    }

    *sig_len = (uint16_t)len;
    return 0;
}

void cred_key_free(struct cred_key *key)
{
    if (key == NULL || !key->live)
        return;

    switch (key->alg->id) {
#if defined(HAVE_ECC256) || defined(HAVE_ECC384) || defined(HAVE_ECC521)
        case CRED_ALG_ES256:
        case CRED_ALG_ES384:
        case CRED_ALG_ES512:
            wc_ecc_free(&key->k.ecc);
            break;
#endif
#ifdef HAVE_ED25519
        case CRED_ALG_ED25519:
            wc_ed25519_free(&key->k.ed);
            break;
#endif
#ifdef WOLFSSL_HAVE_MLDSA
        case CRED_ALG_MLDSA44:
        case CRED_ALG_MLDSA65:
        case CRED_ALG_MLDSA87:
            wc_MlDsaKey_Free(key->mldsa);
            break;
#endif
        default:
            break;
    }
    ForceZero(key, sizeof(*key));
}
