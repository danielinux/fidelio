/* CTAP2 handling (minimal) */

#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "ctap2.h"
#include "device_state.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/kdf.h"
#include "cert.h"
#include "pins.h"
#include "flash_rt.h"
#include "pico/stdlib.h"
#include "hardware/gpio.h"
#include "hardware/flash.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "fdo.h"
#include "indicator.h"
#include "cred_alg.h"
#include "cred_store.h"
#include "wolfssl/wolfcrypt/puf.h"
#include "wolfcose/wolfcose.h"

extern void ForceZero(void* mem, word32 len);

/* CTAP2 status codes (subset). */
#define CTAP2_ERR_SUCCESS            0x00
#define CTAP2_ERR_INVALID_COMMAND    0x01
#define CTAP2_ERR_INVALID_LENGTH     0x03
#define CTAP2_ERR_UNSUPPORTED_ALGORITHM 0x26
#define CTAP2_ERR_PIN_REQUIRED       0x36
#define CTAP2_ERR_INVALID_CBOR       0x12
#define CTAP2_ERR_NO_CREDENTIALS     0x2E
#define CTAP2_ERR_PIN_INVALID        0x31
#define CTAP2_ERR_PIN_BLOCKED        0x34
#define CTAP2_ERR_PIN_NOT_SET        0x35
#define CTAP2_ERR_PIN_AUTH_INVALID   0x33
#define CTAP2_ERR_KEY_STORE_FULL     0x28

#define CTAP2_PIN_PROTOCOL_SUPPORTED 1
#define CTAP2_CMD_MAKE_CREDENTIAL    0x01
#define CTAP2_CMD_GET_ASSERTION      0x02
#define CTAP2_CMD_GET_INFO           0x04
#define CTAP2_CMD_CLIENT_PIN         0x06

#define PUBKEY_SZ 65
#define PARAM_SZ  32
#define ECC_SZ    32
#define HASH_SZ   32
#define NONCE_SZ  32
#define SIGMAX_SZ 75

/* COSE key parameters */
#define COSE_KEY_KTY_LABEL 1
#define COSE_KEY_ALG_LABEL 3
#define COSE_KEY_CRV_LABEL -1
#define COSE_KEY_X_LABEL   -2
#define COSE_KEY_Y_LABEL   -3

#define COSE_KTY_EC2 2
#define COSE_ALG_ES256 -7
#define COSE_CRV_P256 1
#define COSE_ALG_ECDH_ES_HKDF256 -25

#define FLASH_PIN_OFF      0x73000
#define FLASH_PIN_MAGIC    0x50494E21 /* 'PIN!' */
#define PIN_MAX_RETRIES    8
#define FLASH_RK_OFF       0x74000
#define FLASH_RK_MAGIC     0x524B2121 /* 'RK!!' */
#define RK_MAX_SLOTS       8

#define CTAP2_CMD_RESET           0x07

/* Credential ID: alg(1) || nonce(32) || tag(32).
 *
 * Fidelio stores nothing per credential, so the ID must carry everything
 * needed to reconstruct the key: which algorithm it is, and the nonce that
 * salts the derivation. The tag is a MAC over both under the device master
 * secret, so an attacker can neither forge a credential for another relying
 * party nor rewrite the algorithm byte to force a downgrade to the weakest
 * one on offer. It is also checked before any key derivation runs, so a
 * bogus ID costs a HMAC rather than an ML-DSA keygen.
 */
#define CRED_ID_LEN CRED_ID_LEN_MAX


/* CBOR (RFC 8949) encoding and decoding is provided by wolfCOSE. The thin
 * wrappers below only set up a WOLFCOSE_CBOR_CTX and keep the call sites
 * readable; wolfCOSE returns WOLFCOSE_SUCCESS (0) or a negative error code,
 * which matches the 0/-1 convention used throughout this file.
 */
static void cbor_enc_init(WOLFCOSE_CBOR_CTX *c, uint8_t *buf, uint16_t cap,
                          uint16_t off)
{
    c->buf = buf;
    c->cbuf = NULL;
    c->bufSz = cap;
    c->idx = off;
}

static void cbor_dec_init(WOLFCOSE_CBOR_CTX *c, const uint8_t *buf, uint16_t len)
{
    c->buf = NULL;
    c->cbuf = buf;
    c->bufSz = len;
    c->idx = 0;
}

/* Text strings in CTAP2 replies are all string literals. */
static int cbor_put_text(WOLFCOSE_CBOR_CTX *c, const char *s)
{
    return wc_CBOR_EncodeTstr(c, (const uint8_t *)s, strlen(s));
}

static int cbor_put_bool(WOLFCOSE_CBOR_CTX *c, bool v)
{
    return v ? wc_CBOR_EncodeTrue(c) : wc_CBOR_EncodeFalse(c);
}

/* Read a byte string, rejecting anything that does not fit a uint16_t length.
 * Every bstr this authenticator accepts is far below that bound.
 */
static int cbor_read_bytes(WOLFCOSE_CBOR_CTX *c, const uint8_t **out,
                           uint32_t *out_len)
{
    const uint8_t *d;
    size_t dlen;
    if (wc_CBOR_DecodeBstr(c, &d, &dlen) != WOLFCOSE_SUCCESS)
        return -1;
    if (dlen > UINT16_MAX)
        return -1;
    *out = d;
    *out_len = (uint32_t)dlen;
    return 0;
}

static int cbor_read_text(WOLFCOSE_CBOR_CTX *c, const uint8_t **out,
                          uint32_t *out_len)
{
    const uint8_t *d;
    size_t dlen;
    if (wc_CBOR_DecodeTstr(c, &d, &dlen) != WOLFCOSE_SUCCESS)
        return -1;
    if (dlen > UINT16_MAX)
        return -1;
    *out = d;
    *out_len = (uint32_t)dlen;
    return 0;
}

/* Read a definite-length map header, bounding the entry count so a malformed
 * request cannot spin the per-entry loops.
 */
static int cbor_read_map(WOLFCOSE_CBOR_CTX *c, uint32_t *items)
{
    size_t count;
    if (wc_CBOR_DecodeMapStart(c, &count) != WOLFCOSE_SUCCESS)
        return -1;
    if (count > c->bufSz)
        return -1;
    *items = (uint32_t)count;
    return 0;
}

static int cbor_read_array(WOLFCOSE_CBOR_CTX *c, uint32_t *items)
{
    size_t count;
    if (wc_CBOR_DecodeArrayStart(c, &count) != WOLFCOSE_SUCCESS)
        return -1;
    if (count > c->bufSz)
        return -1;
    *items = (uint32_t)count;
    return 0;
}

/* Skip one complete item and hand back the slice it occupied, so callers can
 * re-parse it later (allowList entries, embedded COSE_Key maps).
 */
static int cbor_skip_slice(WOLFCOSE_CBOR_CTX *c, const uint8_t **slice,
                           uint16_t *slice_len)
{
    size_t start = c->idx;
    if (wc_CBOR_Skip(c) != WOLFCOSE_SUCCESS)
        return -1;
    if ((c->idx - start) > UINT16_MAX)
        return -1;
    if (slice)
        *slice = c->cbuf + start;
    if (slice_len)
        *slice_len = (uint16_t)(c->idx - start);
    return 0;
}

static int write_error(uint8_t code, uint8_t *reply, uint16_t *reply_len)
{
    reply[0] = code;
    *reply_len = 1;
    return 0;
}

/* --- Crypto/credential helpers --- */
/* Constant-time equality for anything an attacker can iterate against: PIN
 * hashes, pinAuth and hmac-secret MACs, and credential tags. A plain memcmp
 * returns early on the first differing byte, which leaks how much of a guess
 * was correct and turns an exhaustive search into a per-byte one.
 */
static int ct_memeq(const uint8_t *a, const uint8_t *b, uint16_t len)
{
    uint8_t diff = 0;
    uint16_t i;
    for (i = 0; i < len; i++)
        diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

struct pin_state {
    uint32_t magic;
    uint8_t pin_hash[HASH_SZ];
    uint8_t retries;
    uint8_t reserved[3];
};

static struct pin_state pin_store;
static bool pin_loaded = false;
static bool pin_token_valid = false;
/* Consecutive pinAuth (token) failures. RAM only and reset on success; see
 * pin_require_for_op().
 */
#define PIN_AUTH_MAX_FAILS 3
static uint8_t pin_auth_fails = 0;
static uint8_t pin_token[32];

static ecc_key pin_agree_key;
static uint8_t pin_agree_qx[ECC_SZ];
static uint8_t pin_agree_qy[ECC_SZ];
static bool pin_agree_valid = false;
static bool pin_agree_consumed = true;

static void pin_state_reset(void)
{
    memset(&pin_store, 0, sizeof(pin_store));
    pin_loaded = false;
    pin_token_valid = false;
    pin_auth_fails = 0;
    ForceZero(pin_token, sizeof(pin_token));
    pin_agree_valid = false;
    pin_agree_consumed = true;
    fidelio_flash_erase(FLASH_PIN_OFF, FLASH_SECTOR_SIZE);
}

static void pin_state_load(void)
{
    if (pin_loaded)
        return;
    const struct pin_state *flash_pin = (const struct pin_state *)(XIP_BASE + FLASH_PIN_OFF);
    if (flash_pin->magic == FLASH_PIN_MAGIC) {
        memcpy(&pin_store, flash_pin, sizeof(pin_store));
    } else {
        memset(&pin_store, 0, sizeof(pin_store));
        pin_store.retries = PIN_MAX_RETRIES;
    }
    pin_loaded = true;
}

static void pin_state_save(void)
{
    pin_store.magic = FLASH_PIN_MAGIC;
    fidelio_flash_erase(FLASH_PIN_OFF, FLASH_SECTOR_SIZE);
    fidelio_flash_program(FLASH_PIN_OFF, (const uint8_t *)&pin_store, sizeof(pin_store));
}

static void pin_reset_token(WC_RNG *rng)
{
    wc_RNG_GenerateBlock(rng, pin_token, sizeof(pin_token));
    pin_token_valid = true;
    pin_auth_fails = 0;
}

static int pin_generate_agreement_key(WC_RNG *rng)
{
    if (!pin_agree_valid) {
        wc_ecc_init(&pin_agree_key);
    } else {
        wc_ecc_free(&pin_agree_key);
        wc_ecc_init(&pin_agree_key);
    }
    if (wc_ecc_make_key_ex(rng, ECC_SZ, &pin_agree_key, ECC_SECP256R1) != 0)
        return -1;
    word32 qxlen = ECC_SZ, qylen = ECC_SZ;
    if (wc_ecc_export_public_raw(&pin_agree_key, pin_agree_qx, &qxlen, pin_agree_qy, &qylen) != 0)
        return -1;
    pin_agree_valid = true;
    pin_agree_consumed = false;
    return 0;
}

static int pin_shared_secret(const uint8_t *peer_x, const uint8_t *peer_y, uint8_t *secret_out)
{
    int ret;
    ecc_key peer;
    uint8_t ecdh[ECC_SZ * 2];
    word32 ecdh_len = sizeof(ecdh);
    uint8_t z[32];
    if (!pin_agree_valid)
        return -1;
    wc_ecc_init(&peer);
    ret = wc_ecc_import_unsigned(&peer, peer_x, peer_y, NULL, ECC_SECP256R1);
    if (ret != 0) {
        wc_ecc_free(&peer);
        return -1;
    }
    ret = wc_ecc_shared_secret(&pin_agree_key, &peer, ecdh, &ecdh_len);
    wc_ecc_free(&peer);
    if (ret != 0)
        return -1;
    /* Protocol 1: sharedSecret = SHA256(ECDH), used for both HMAC and AES keys */
    uint8_t ss[HASH_SZ];
    if (wc_Sha256Hash(ecdh, ecdh_len, ss) != 0)
        return -1;
    memcpy(secret_out, ss, HASH_SZ);
    memcpy(secret_out + HASH_SZ, ss, HASH_SZ);
    ForceZero(ecdh, sizeof(ecdh));
    ForceZero(z, sizeof(z));
    ForceZero(ss, sizeof(ss));
    return 0;
}

static int pin_encrypt(const uint8_t *key, const uint8_t *in, uint16_t in_len, uint8_t *out, uint16_t *out_len, WC_RNG *rng)
{
    Aes aes;
    uint8_t iv[16];
    int ret;
    if (wc_RNG_GenerateBlock(rng, iv, sizeof(iv)) != 0)
        return -1;
    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0)
        return ret;
    ret = wc_AesSetKey(&aes, key, 32, iv, AES_ENCRYPTION);
    if (ret != 0) {
        wc_AesFree(&aes);
        return ret;
    }
    memcpy(out, iv, sizeof(iv));
    ret = wc_AesCbcEncrypt(&aes, out + sizeof(iv), in, in_len);
    wc_AesFree(&aes);
    *out_len = (uint16_t)(sizeof(iv) + in_len);
    return ret;
}

static int pin_decrypt(const uint8_t *key, const uint8_t *in, uint16_t in_len, uint8_t *out, uint16_t *out_len)
{
    Aes aes;
    uint8_t iv[16];
    int ret;
    if (in_len < sizeof(iv) || ((in_len - sizeof(iv)) % 16) != 0)
        return -1;
    memcpy(iv, in, sizeof(iv));
    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0)
        return ret;
    ret = wc_AesSetKey(&aes, key, 32, iv, AES_DECRYPTION);
    if (ret != 0) {
        wc_AesFree(&aes);
        return ret;
    }
    ret = wc_AesCbcDecrypt(&aes, out, in + sizeof(iv), in_len - sizeof(iv));
    wc_AesFree(&aes);
    if (ret == 0 && out_len)
        *out_len = (uint16_t)(in_len - sizeof(iv));
    return ret;
}

static int pin_hash_plain(const uint8_t *pin, uint16_t pin_len, uint8_t *hash_out)
{
    return wc_Sha256Hash(pin, pin_len, hash_out);
}

/* Spend a retry BEFORE checking the guess, and persist it immediately.
 *
 * Decrementing afterwards is exploitable: an attacker sends a wrong PIN and
 * cuts power the moment the device starts responding, so the flash write
 * never lands and the counter never moves. Repeat for unlimited guesses.
 * Charging the attempt up front makes a power cut cost a retry rather than
 * refund one. pin_restore_retries() gives them back only on success.
 */
static int pin_spend_retry(void)
{
    pin_state_load();
    if (pin_store.retries == 0)
        return -1;
    pin_store.retries--;
    pin_state_save();
    return 0;
}

static void pin_restore_retries(void)
{
    if (pin_store.retries != PIN_MAX_RETRIES) {
        pin_store.retries = PIN_MAX_RETRIES;
        pin_state_save();
    }
}

static int pin_require_for_op(const uint8_t *pin_auth, uint32_t pin_auth_len,
                              const uint8_t *cdh, uint32_t cdh_len, bool require_pin, bool *verified)
{
    Hmac hmac;
    uint8_t mac[HASH_SZ];
    pin_state_load();
    if (pin_store.magic != FLASH_PIN_MAGIC) {
        return 0; /* no PIN set */
    }
    /* If UV not requested and no pinAuth provided, allow UV=0 path. */
    if (!require_pin && (!pin_auth || pin_auth_len == 0)) {
        if (verified) *verified = false;
        return 0;
    }
    if (!pin_token_valid)
        return CTAP2_ERR_PIN_REQUIRED;
    /* Protocol 1 uses 16-byte pinAuth (truncated HMAC-SHA256); accept 32 and truncate. */
    if (!pin_auth || (pin_auth_len != 16 && pin_auth_len != 32))
        return CTAP2_ERR_PIN_REQUIRED;
    if (wc_HmacInit(&hmac, NULL, 0) != 0)
        return CTAP2_ERR_PIN_AUTH_INVALID;
    if (wc_HmacSetKey(&hmac, SHA256, pin_token, sizeof(pin_token)) != 0) {
        wc_HmacFree(&hmac);
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    wc_HmacUpdate(&hmac, cdh, cdh_len);
    wc_HmacFinal(&hmac, mac);
    wc_HmacFree(&hmac);
    if (!ct_memeq(mac, pin_auth, 16)) {
        ForceZero(mac, sizeof(mac));
        /* This checks pinAuth against the pinToken, not the PIN, so it must
         * NOT spend a persistent PIN retry: that counter guards PIN entry.
         * CTAP2 instead drops the token after repeated failures, forcing the
         * platform to prove the PIN again. Keeping the count in RAM also
         * avoids two flash sector erases on every authenticated operation.
         */
        if (++pin_auth_fails >= PIN_AUTH_MAX_FAILS) {
            pin_token_valid = false;
            pin_auth_fails = 0;
        }
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    ForceZero(mac, sizeof(mac));
    pin_auth_fails = 0;
    if (verified)
        *verified = true;
    return 0;
}
static int cred_tag(uint8_t alg_id, const uint8_t *rpIdHash,
                    const uint8_t *nonce, uint8_t *tag_out)
{
    Hmac hmac;
    const uint8_t *secret = device_get_secret();
    int ret;

    if (secret == NULL)
        return -1;
    ret = wc_HmacInit(&hmac, NULL, 0);
    if (ret != 0)
        return -1;
    ret = wc_HmacSetKey(&hmac, WC_SHA256, secret, WC_PUF_KEY_SZ);
    if (ret == 0) {
        wc_HmacUpdate(&hmac, &alg_id, 1);
        wc_HmacUpdate(&hmac, rpIdHash, HASH_SZ);
        wc_HmacUpdate(&hmac, nonce, NONCE_SZ);
        ret = wc_HmacFinal(&hmac, tag_out);
    }
    wc_HmacFree(&hmac);
    return (ret == 0) ? 0 : -1;
}

/* Validate a credential ID against this relying party and, if it checks out,
 * derive the key it names.
 */
static int cred_open(const uint8_t *credId, uint16_t credIdLen,
                     const uint8_t *rpIdHash, struct cred_key *key_out,
                     const struct cred_alg **alg_out)
{
    const struct cred_alg *alg;
    uint8_t tag[HASH_SZ];
    int ok;

    if (credIdLen != CRED_ID_LEN)
        return -1;
    alg = cred_alg_by_id(credId[0]);
    if (alg == NULL)
        return -1;
    if (cred_tag(credId[0], rpIdHash, credId + 1, tag) != 0)
        return -1;
    ok = ct_memeq(tag, credId + 1 + NONCE_SZ, HASH_SZ);
    ForceZero(tag, sizeof(tag));
    if (!ok)
        return -1;
    if (cred_alg_derive(alg, device_get_secret(), rpIdHash, credId + 1,
                        key_out) != 0)
        return -1;
    if (alg_out)
        *alg_out = alg;
    return 0;
}

/* hmac-secret's per-credential seed. Bound to the master secret rather than
 * to the credential private key, so it is independent of the algorithm and
 * does not require the signing key to still be in scope.
 */
static int derive_cred_random(const uint8_t *rpIdHash, const uint8_t *credId,
                              uint16_t credIdLen, uint8_t *cred_random)
{
    Hmac hmac;
    const uint8_t *secret = device_get_secret();
    static const char label[] = "fidelio-hmac-secret";
    int ret;

    if (secret == NULL)
        return -1;
    if (wc_HmacInit(&hmac, NULL, 0) != 0)
        return -1;
    ret = wc_HmacSetKey(&hmac, WC_SHA256, secret, WC_PUF_KEY_SZ);
    if (ret == 0) {
        wc_HmacUpdate(&hmac, (const byte *)label, sizeof(label) - 1);
        wc_HmacUpdate(&hmac, rpIdHash, HASH_SZ);
        wc_HmacUpdate(&hmac, credId, credIdLen);
        ret = wc_HmacFinal(&hmac, cred_random);
    }
    wc_HmacFree(&hmac);
    return (ret == 0) ? 0 : -1;
}

static int build_credential_id(WC_RNG *rng, const struct cred_alg *alg,
                               const uint8_t *rpIdHash, uint8_t *credId,
                               uint16_t credIdCap, uint16_t *credIdLen)
{
    if (credIdCap < CRED_ID_LEN)
        return -1;
    if (wc_RNG_GenerateBlock(rng, credId + 1, NONCE_SZ) != 0)
        return -1;
    credId[0] = alg->id;
    if (cred_tag(alg->id, rpIdHash, credId + 1, credId + 1 + NONCE_SZ) != 0)
        return -1;
    *credIdLen = CRED_ID_LEN;
    return 0;
}

/* Serialise a P-256 public key as a COSE_Key map via wolfCOSE. The emitted
 * map is {1: 2, 3: alg, -1: 1, -2: qx, -3: qy}, which is the CTAP2 canonical
 * CBOR key order (all labels encode to one byte: 0x01 0x03 0x20 0x21 0x22).
 * Takes the live ecc_key so no point re-import is needed on the hot paths.
 */
static int encode_cose_pubkey(WOLFCOSE_CBOR_CTX *c, ecc_key *ecc, int32_t alg)
{
    WOLFCOSE_KEY key;
    size_t written = 0;

    if (wc_CoseKey_Init(&key) != WOLFCOSE_SUCCESS)
        return -1;
    if (wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, ecc) != WOLFCOSE_SUCCESS)
        return -1;
    key.alg = alg;
    /* Both callers pass a key that still holds its private scalar.
     * wc_CoseKey_SetEcc() sets hasPrivate for those, and wc_CoseKey_Encode()
     * would then serialise -4:d into a reply that goes out over USB. This
     * serialiser is public-key-only by contract, so clear it explicitly.
     */
    key.hasPrivate = 0;
    if (wc_CoseKey_Encode(&key, c->buf + c->idx, c->bufSz - c->idx,
                          &written) != WOLFCOSE_SUCCESS)
        return -1;
    c->idx += written;
    return 0;
}

static int build_authdata_attested(const uint8_t *rpIdHash, uint8_t flags, uint32_t counter,
                                   const uint8_t *credId, uint16_t credIdLen,
                                   struct cred_key *pubkey,
                                   uint8_t *authData, uint16_t authDataCap, uint16_t *authDataLen)
{
    uint8_t aaguid[16] = {0};
    uint16_t idx = 0;
    uint8_t counter_be[4];
    WOLFCOSE_CBOR_CTX cose;

    counter_be[0] = (uint8_t)((counter >> 24) & 0xFF);
    counter_be[1] = (uint8_t)((counter >> 16) & 0xFF);
    counter_be[2] = (uint8_t)((counter >> 8) & 0xFF);
    counter_be[3] = (uint8_t)(counter & 0xFF);

    if (authDataCap < (HASH_SZ + 1 + 4 + 16 + 2 + credIdLen))
        return -1;

    memcpy(&authData[idx], rpIdHash, HASH_SZ);
    idx += HASH_SZ;
    authData[idx++] = flags;
    memcpy(&authData[idx], counter_be, 4);
    idx += 4;
    memcpy(&authData[idx], aaguid, sizeof(aaguid));
    idx += sizeof(aaguid);
    authData[idx++] = (uint8_t)(credIdLen >> 8);
    authData[idx++] = (uint8_t)(credIdLen & 0xFF);
    memcpy(&authData[idx], credId, credIdLen);
    idx += credIdLen;

    cbor_enc_init(&cose, &authData[idx], (uint16_t)(authDataCap - idx), 0);
    if (cred_alg_pubkey_cose(pubkey, &cose) != 0)
        return -1;
    idx += (uint16_t)cose.idx;
    *authDataLen = idx;
    return 0;
}

static int build_authdata_assert(const uint8_t *rpIdHash, uint8_t flags, uint32_t counter,
                                 const uint8_t *ext, uint16_t ext_len,
                                 uint8_t *authData, uint16_t authDataCap, uint16_t *authDataLen)
{
    uint8_t counter_be[4];
    uint16_t needed = HASH_SZ + 1 + 4;
    uint8_t flags_out = flags;
    if (ext && ext_len > 0) {
        flags_out |= 0x80; /* ED */
        needed = (uint16_t)(needed + ext_len);
    }
    if (authDataCap < needed)
        return -1;
    counter_be[0] = (uint8_t)((counter >> 24) & 0xFF);
    counter_be[1] = (uint8_t)((counter >> 16) & 0xFF);
    counter_be[2] = (uint8_t)((counter >> 8) & 0xFF);
    counter_be[3] = (uint8_t)(counter & 0xFF);

    memcpy(authData, rpIdHash, HASH_SZ);
    authData[HASH_SZ] = flags_out;
    memcpy(&authData[HASH_SZ + 1], counter_be, 4);
    if (ext && ext_len > 0) {
        memcpy(&authData[HASH_SZ + 1 + 4], ext, ext_len);
        *authDataLen = (uint16_t)(HASH_SZ + 1 + 4 + ext_len);
    } else {
        *authDataLen = (uint16_t)(HASH_SZ + 1 + 4);
    }
    return 0;
}

/* Decode a platform-supplied COSE_Key (P-256) into raw qx/qy. wolfCOSE checks
 * kty/crv against the attached key type and imports the point; the import
 * itself rejects anything that is not on the curve.
 */
static int parse_cose_pubkey(const uint8_t *buf, uint16_t len, uint8_t *qx, uint8_t *qy)
{
    WOLFCOSE_KEY key;
    ecc_key ecc;
    word32 qxlen = ECC_SZ, qylen = ECC_SZ;
    int ret = -1;

    if (wc_ecc_init(&ecc) != 0)
        return -1;
    if (wc_CoseKey_Init(&key) != WOLFCOSE_SUCCESS)
        goto out;
    if (wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &ecc) != WOLFCOSE_SUCCESS)
        goto out;
    if (wc_CoseKey_Decode(&key, buf, len) != WOLFCOSE_SUCCESS)
        goto out;
    if (key.kty != WOLFCOSE_KTY_EC2 || key.crv != WOLFCOSE_CRV_P256)
        goto out;
    /* alg is optional in a CTAP2 keyAgreement key; reject only a wrong one. */
    if (key.alg != 0 && key.alg != COSE_ALG_ECDH_ES_HKDF256 &&
        key.alg != COSE_ALG_ES256)
        goto out;
    if (wc_ecc_export_public_raw(&ecc, qx, &qxlen, qy, &qylen) != 0)
        goto out;
    if (qxlen != ECC_SZ || qylen != ECC_SZ)
        goto out;
    ret = 0;

out:
    wc_ecc_free(&ecc);
    return ret;
}

struct mc_params {
    const uint8_t *clientDataHash;
    uint32_t cdh_len;
    const uint8_t *rp_id;
    uint32_t rp_id_len;
    uint32_t alg_mask;   /* bitmap of (1u << CRED_ALG_*) the RP accepts */
    bool uv_required;
    const uint8_t *pin_auth;
    uint32_t pin_auth_len;
    int pin_protocol;
    const uint8_t *user_handle;
    uint32_t user_handle_len;
    const uint8_t *user_name;
    uint32_t user_name_len;
    bool rk;
};

struct ga_params {
    const uint8_t *clientDataHash;
    uint32_t cdh_len;
    const uint8_t *rp_id;
    uint32_t rp_id_len;
    const uint8_t *cred_id;
    uint32_t cred_id_len;
    bool uv_required;
    const uint8_t *pin_auth;
    uint32_t pin_auth_len;
    int pin_protocol;
    bool allow_rk;
    const uint8_t *allow_list;
    uint32_t allow_list_len;
    uint32_t allow_count;
    bool hmac_secret_requested;
    bool hmac_secret_valid;
    uint8_t hs_platform_qx[ECC_SZ];
    uint8_t hs_platform_qy[ECC_SZ];
    bool hs_key_set;
    const uint8_t *hs_salt_enc;
    uint32_t hs_salt_enc_len;
    const uint8_t *hs_salt_auth;
    uint32_t hs_salt_auth_len;
    int hs_pin_protocol;
};

/* Read a map key that may be encoded either as an unsigned int (CTAP2
 * canonical) or as a text label, which some clients still emit inside
 * pubKeyCredParams and allowList entries.
 */
struct cbor_key {
    bool is_text;
    uint64_t num;
    const uint8_t *text;
    uint32_t text_len;
};

static int cbor_read_key(WOLFCOSE_CBOR_CTX *c, struct cbor_key *k)
{
    memset(k, 0, sizeof(*k));
    switch (wc_CBOR_PeekType(c)) {
        case WOLFCOSE_CBOR_UINT:
            if (wc_CBOR_DecodeUint(c, &k->num) != WOLFCOSE_SUCCESS)
                return -1;
            return 0;
        case WOLFCOSE_CBOR_TSTR:
            k->is_text = true;
            return cbor_read_text(c, &k->text, &k->text_len);
        default:
            return -1;
    }
}

static bool cbor_key_is(const struct cbor_key *k, uint64_t num, const char *lit)
{
    if (!k->is_text)
        return k->num == num;
    return k->text_len == strlen(lit) &&
           memcmp(k->text, lit, k->text_len) == 0;
}

/* Read a CBOR true/false into *out, leaving *out untouched for other types. */
static int cbor_read_bool(WOLFCOSE_CBOR_CTX *c, bool *out)
{
    WOLFCOSE_CBOR_ITEM item;
    if (wc_CBOR_DecodeHead(c, &item) != WOLFCOSE_SUCCESS)
        return -1;
    if (item.majorType == WOLFCOSE_CBOR_SIMPLE && item.val == 21)
        *out = true;
    return 0;
}

static int parse_makecred(const uint8_t *buf, uint16_t len, struct mc_params *out)
{
    WOLFCOSE_CBOR_CTX c;
    uint32_t items;

    memset(out, 0, sizeof(*out));
    cbor_dec_init(&c, buf, len);
    if (cbor_read_map(&c, &items) != 0)
        return -1;

    for (uint32_t i = 0; i < items; i++) {
        uint64_t key;
        if (wc_CBOR_DecodeUint(&c, &key) != WOLFCOSE_SUCCESS)
            return -1;

        switch (key) {
            case 1: /* clientDataHash */
                if (cbor_read_bytes(&c, &out->clientDataHash, &out->cdh_len) != 0)
                    return -1;
                break;
            case 2: { /* rp */
                uint32_t mitems;
                if (cbor_read_map(&c, &mitems) != 0)
                    return -1;
                for (uint32_t j = 0; j < mitems; j++) {
                    const uint8_t *t; uint32_t tlen;
                    if (cbor_read_text(&c, &t, &tlen) != 0)
                        return -1;
                    if (tlen == 2 && t[0] == 'i' && t[1] == 'd') {
                        if (cbor_read_text(&c, &out->rp_id, &out->rp_id_len) != 0)
                            return -1;
                    } else if (wc_CBOR_Skip(&c) != WOLFCOSE_SUCCESS) {
                        return -1;
                    }
                }
                break;
            }
            case 3: { /* user */
                uint32_t mitems;
                if (cbor_read_map(&c, &mitems) != 0)
                    return -1;
                for (uint32_t j = 0; j < mitems; j++) {
                    const uint8_t *t; uint32_t tlen;
                    if (cbor_read_text(&c, &t, &tlen) != 0)
                        return -1;
                    if (tlen == 2 && memcmp(t, "id", 2) == 0) {
                        if (cbor_read_bytes(&c, &out->user_handle,
                                            &out->user_handle_len) != 0)
                            return -1;
                    } else if (tlen == 4 && memcmp(t, "name", 4) == 0) {
                        if (cbor_read_text(&c, &out->user_name,
                                           &out->user_name_len) != 0)
                            return -1;
                    } else if (wc_CBOR_Skip(&c) != WOLFCOSE_SUCCESS) {
                        return -1;
                    }
                }
                break;
            }
            case 4: { /* pubKeyCredParams */
                uint32_t acount;
                if (cbor_read_array(&c, &acount) != 0)
                    return -1;
                for (uint32_t j = 0; j < acount; j++) {
                    uint32_t mitems;
                    bool type_ok = false;
                    bool alg_ok = false;
                    uint8_t cand = 0;
                    if (cbor_read_map(&c, &mitems) != 0)
                        return -1;
                    for (uint32_t k = 0; k < mitems; k++) {
                        struct cbor_key mkey;
                        if (cbor_read_key(&c, &mkey) != 0)
                            return -1;
                        if (cbor_key_is(&mkey, 1, "type")) {
                            const uint8_t *tv; uint32_t tvlen;
                            if (cbor_read_text(&c, &tv, &tvlen) != 0)
                                return -1;
                            if (tvlen == 10 && memcmp(tv, "public-key", 10) == 0)
                                type_ok = true;
                        } else if (cbor_key_is(&mkey, 3, "alg")) {
                            int64_t aval;
                            if (wc_CBOR_DecodeInt(&c, &aval) != WOLFCOSE_SUCCESS)
                                return -1;
                            {
                                const struct cred_alg *a =
                                    cred_alg_by_cose((int32_t)aval);
                                if (a != NULL) {
                                    alg_ok = true;
                                    cand = a->id;
                                }
                            }
                        } else if (wc_CBOR_Skip(&c) != WOLFCOSE_SUCCESS) {
                            return -1;
                        }
                    }
                    /* Record every algorithm the RP will accept; the
                     * strongest is chosen once the whole list is known. */
                    if (type_ok && alg_ok && cand != 0)
                        out->alg_mask |= (1u << cand);
                }
                break;
            }
            case 7: { /* options */
                uint32_t mitems;
                if (cbor_read_map(&c, &mitems) != 0)
                    return -1;
                for (uint32_t j = 0; j < mitems; j++) {
                    const uint8_t *tn; uint32_t tnlen;
                    if (cbor_read_text(&c, &tn, &tnlen) != 0)
                        return -1;
                    if (tnlen == 2 && tn[0] == 'u' && tn[1] == 'v') {
                        if (cbor_read_bool(&c, &out->uv_required) != 0)
                            return -1;
                    } else if (tnlen == 2 && tn[0] == 'r' && tn[1] == 'k') {
                        if (cbor_read_bool(&c, &out->rk) != 0)
                            return -1;
                    } else if (wc_CBOR_Skip(&c) != WOLFCOSE_SUCCESS) {
                        return -1;
                    }
                }
                break;
            }
            case 8: /* pinAuth */
                if (cbor_read_bytes(&c, &out->pin_auth, &out->pin_auth_len) != 0)
                    return -1;
                break;
            case 9: { /* pinProtocol */
                uint64_t v;
                if (wc_CBOR_DecodeUint(&c, &v) != WOLFCOSE_SUCCESS)
                    return -1;
                out->pin_protocol = (int)v;
                break;
            }
            default:
                if (wc_CBOR_Skip(&c) != WOLFCOSE_SUCCESS)
                    return -1;
                break;
        }
    }

    if (!out->clientDataHash || out->cdh_len != HASH_SZ)
        return -1;
    if (!out->rp_id || out->rp_id_len == 0)
        return -1;
    if (out->alg_mask == 0)
        return -1;
    return 0;
}

static int parse_hmac_secret_input(const uint8_t *buf, uint16_t len, struct ga_params *out)
{
    WOLFCOSE_CBOR_CTX c;
    uint32_t items;

    cbor_dec_init(&c, buf, len);
    if (cbor_read_map(&c, &items) != 0)
        return -1;

    for (uint32_t i = 0; i < items; i++) {
        struct cbor_key key;
        uint32_t iitems;

        if (cbor_read_key(&c, &key) != 0)
            return -1;
        /* The extension is always identified by its text name. */
        if (!key.is_text || !cbor_key_is(&key, 0, "hmac-secret")) {
            if (wc_CBOR_Skip(&c) != WOLFCOSE_SUCCESS)
                return -1;
            continue;
        }

        /* Parse inner hmac-secret map */
        if (cbor_read_map(&c, &iitems) != 0)
            return -1;
        for (uint32_t j = 0; j < iitems; j++) {
            struct cbor_key ikey;
            if (cbor_read_key(&c, &ikey) != 0)
                return -1;

            if (cbor_key_is(&ikey, 1, "keyAgreement")) {
                const uint8_t *slice; uint16_t slice_len;
                if (cbor_skip_slice(&c, &slice, &slice_len) != 0)
                    return -1;
                if (parse_cose_pubkey(slice, slice_len, out->hs_platform_qx,
                                      out->hs_platform_qy) != 0)
                    return -1;
                out->hmac_secret_requested = true;
                out->hs_key_set = true;
            } else if (cbor_key_is(&ikey, 2, "saltEnc")) {
                if (cbor_read_bytes(&c, &out->hs_salt_enc, &out->hs_salt_enc_len) != 0)
                    return -1;
                if (out->hs_salt_enc_len != 32 && out->hs_salt_enc_len != 64)
                    return -1;
                out->hmac_secret_requested = true;
            } else if (cbor_key_is(&ikey, 3, "saltAuth")) {
                if (cbor_read_bytes(&c, &out->hs_salt_auth, &out->hs_salt_auth_len) != 0)
                    return -1;
                if (out->hs_salt_auth_len != 16)
                    return -1;
                out->hmac_secret_requested = true;
            } else if (cbor_key_is(&ikey, 4, "pinProtocol")) {
                uint64_t v;
                if (wc_CBOR_DecodeUint(&c, &v) != WOLFCOSE_SUCCESS)
                    return -1;
                out->hs_pin_protocol = (int)v;
                out->hmac_secret_requested = true;
            } else if (wc_CBOR_Skip(&c) != WOLFCOSE_SUCCESS) {
                return -1;
            }
        }
    }

    if (out->hmac_secret_requested &&
        out->hs_key_set &&
        out->hs_salt_enc && out->hs_salt_auth) {
        out->hmac_secret_valid = true;
    }
    return 0;
}

static int parse_getassert(const uint8_t *buf, uint16_t len, struct ga_params *out)
{
    WOLFCOSE_CBOR_CTX c;
    uint32_t items;
    memset(out, 0, sizeof(*out));

    cbor_dec_init(&c, buf, len);
    if (cbor_read_map(&c, &items) != 0)
        return -1;

    for (uint32_t i = 0; i < items; i++) {
        uint64_t key;
        if (wc_CBOR_DecodeUint(&c, &key) != WOLFCOSE_SUCCESS)
            return -1;

        switch (key) {
            case 1: /* rpId */
                if (cbor_read_text(&c, &out->rp_id, &out->rp_id_len) != 0)
                    return -1;
                break;
            case 2: /* clientDataHash */
                if (cbor_read_bytes(&c, &out->clientDataHash, &out->cdh_len) != 0)
                    return -1;
                break;
            case 3: { /* allowList */
                uint32_t acount;
                size_t start;
                if (cbor_read_array(&c, &acount) != 0)
                    return -1;
                if (acount == 0) {
                    out->allow_rk = true;
                    out->allow_list = NULL;
                    out->allow_list_len = 0;
                    out->allow_count = 0;
                    break;
                }
                /* Record the raw array body for the later credential scan. */
                start = c.idx;
                out->allow_list = c.cbuf + start;
                out->allow_count = acount;
                for (uint32_t j = 0; j < acount; j++) {
                    if (wc_CBOR_Skip(&c) != WOLFCOSE_SUCCESS)
                        return -1;
                }
                out->allow_list_len = (uint32_t)(c.idx - start);
                break;
            }
            case 4: { /* extensions */
                const uint8_t *slice; uint16_t slice_len;
                if (cbor_skip_slice(&c, &slice, &slice_len) != 0)
                    return -1;
                if (parse_hmac_secret_input(slice, slice_len, out) != 0)
                    return -1;
                break;
            }
            case 5: { /* options */
                uint32_t mitems;
                if (cbor_read_map(&c, &mitems) != 0)
                    return -1;
                for (uint32_t j = 0; j < mitems; j++) {
                    const uint8_t *tn; uint32_t tnlen;
                    if (cbor_read_text(&c, &tn, &tnlen) != 0)
                        return -1;
                    if (tnlen == 2 && tn[0] == 'u' && tn[1] == 'v') {
                        if (cbor_read_bool(&c, &out->uv_required) != 0)
                            return -1;
                    } else if (wc_CBOR_Skip(&c) != WOLFCOSE_SUCCESS) {
                        return -1;
                    }
                }
                break;
            }
            case 6: /* pinAuth */
                if (cbor_read_bytes(&c, &out->pin_auth, &out->pin_auth_len) != 0)
                    return -1;
                break;
            case 7: { /* pinProtocol */
                uint64_t v;
                if (wc_CBOR_DecodeUint(&c, &v) != WOLFCOSE_SUCCESS)
                    return -1;
                out->pin_protocol = (int)v;
                break;
            }
            default:
                if (wc_CBOR_Skip(&c) != WOLFCOSE_SUCCESS)
                    return -1;
                break;
        }
    }

    if (!out->clientDataHash || out->cdh_len != HASH_SZ)
        return -1;
    if (!out->rp_id || out->rp_id_len == 0)
        return -1;
    if (out->hs_pin_protocol != 0 && out->hs_pin_protocol != CTAP2_PIN_PROTOCOL_SUPPORTED)
        return -1;
    if (out->hmac_secret_requested && !out->hmac_secret_valid)
        return -1;
    /* An absent allowList is not an error: it is how a relying party asks
     * for a discoverable credential. Only an explicitly present but
     * unparseable list is a problem, and that is caught above.
     */
    return 0;
}

/* WebAuthn signature counter: always zero.
 *
 * WebAuthn L3 section 6.1.1 allows a per-credential counter, a global counter,
 * or a global counter with a per-credential increment step, and it permits
 * reporting a constant zero -- which is what synced passkey providers do.
 * Per-credential counters are recommended, but they require per-credential
 * state, and Fidelio deliberately stores none: every credential key is
 * re-derived on demand from the master secret.
 *
 * The counter exists so a relying party can detect a cloned authenticator.
 * Fidelio cannot be cloned, so there is nothing for it to detect:
 *
 *   - The master secret is never stored. It is reconstructed at every boot
 *     from the power-on state of a reserved SRAM block, using the wolfCrypt
 *     BCH(127,50,t=13) fuzzy extractor.
 *   - That power-up state is a physical property of one particular die: it
 *     comes from process variation in the SRAM cells' bias. Measured on this
 *     hardware it is a stable fingerprint -- ~49.7% Hamming weight, 5.9%
 *     inter-boot bit error rate, well inside what the code corrects.
 *   - Flash holds only the helper data and a salt. Neither reveals the key:
 *     in the code-offset construction the helper data is the raw readout
 *     XOR a codeword, and the residual min-entropy of the stable bits stays
 *     above 190 bits even at a pessimistic 0.70 bits/bit SRAM entropy rate.
 *   - Copying the flash to a second RP2040 therefore reproduces the helper
 *     data but not the SRAM response, so reconstruction yields a different
 *     master secret and every derived credential key differs.
 *   - Credential private keys are themselves never stored, in flash or in
 *     the credential ID; they are HKDF-derived per operation.
 *
 * So there is no artifact anywhere that can be copied to produce a second
 * authenticator answering for the same credentials. Reporting zero costs
 * nothing detectable and removes the cross-relying-party correlation that a
 * global counter leaks.
 *
 * The CTAP1/U2F path in u2f.c keeps its own incrementing counter: that
 * protocol's deployed verifiers (pam_u2f among them) reject a counter that
 * fails to advance.
 */
#define CTAP2_SIGN_COUNT 0u

static const uint8_t fidelio_aaguid[16] = {
    0xf1, 0xde, 0x10, 0x01,
    0x42, 0x42, 0x42, 0x42,
    0x99, 0x99, 0xaa, 0xaa,
    0xbb, 0xbb, 0xcc, 0xcc
};

static int ctap2_write_getinfo(uint8_t *reply, uint16_t reply_max, uint16_t *reply_len)
{
    /* reply[0] = status, rest = CBOR */
    WOLFCOSE_CBOR_CTX c;

    if (reply_max < 1)
        return -1;

    /* Reserve status byte at [0]; CBOR starts at [1]. */
    cbor_enc_init(&c, reply, reply_max, 1);
    reply[0] = CTAP2_ERR_SUCCESS;

    /* Map entries: versions, extensions, aaguid, options, maxMsgSize, pinProtocols,
     * maxCredentialCountInList, maxCredentialIdLength
     */
    if (wc_CBOR_EncodeMapStart(&c, 8) != 0) return -1;

    /* 1: versions */
    if (wc_CBOR_EncodeUint(&c, 1) != 0) return -1;
    if (wc_CBOR_EncodeArrayStart(&c, 1) != 0) return -1;
    if (cbor_put_text(&c, "FIDO_2_0") != 0) return -1;
    //if (cbor_put_text(&c, "U2F_V2") != 0) return -1;

    /* 2: extensions */
    if (wc_CBOR_EncodeUint(&c, 2) != 0) return -1;
    if (wc_CBOR_EncodeArrayStart(&c, 1) != 0) return -1;
    if (cbor_put_text(&c, "hmac-secret") != 0) return -1;

    /* 3: aaguid */
    if (wc_CBOR_EncodeUint(&c, 3) != 0) return -1;
    if (wc_CBOR_EncodeBstr(&c, fidelio_aaguid, sizeof(fidelio_aaguid)) != 0) return -1;

    /* 4: options map */
    if (wc_CBOR_EncodeUint(&c, 4) != 0) return -1;
    if (wc_CBOR_EncodeMapStart(&c, 4) != 0) return -1;
    if (cbor_put_text(&c, "rk") != 0) return -1;
    if (cbor_put_bool(&c, true) != 0) return -1;
    if (cbor_put_text(&c, "up") != 0) return -1;
    if (cbor_put_bool(&c, true) != 0) return -1;
    if (cbor_put_text(&c, "uv") != 0) return -1;
    if (cbor_put_bool(&c, false) != 0) return -1;
    if (cbor_put_text(&c, "clientPin") != 0) return -1;
    if (cbor_put_bool(&c, true) != 0) return -1;

    /* 5: maxMsgSize */
    if (wc_CBOR_EncodeUint(&c, 5) != 0) return -1;
    if (wc_CBOR_EncodeUint(&c, CTAP2_MAX_MSG_SIZE) != 0) return -1;

    /* 6: pinProtocols */
    if (wc_CBOR_EncodeUint(&c, 6) != 0) return -1;
    if (wc_CBOR_EncodeArrayStart(&c, 1) != 0) return -1;
    if (wc_CBOR_EncodeUint(&c, CTAP2_PIN_PROTOCOL_SUPPORTED) != 0) return -1;

    /* 7: maxCredentialCountInList */
    if (wc_CBOR_EncodeUint(&c, 7) != 0) return -1;
    if (wc_CBOR_EncodeUint(&c, 8) != 0) return -1;

    /* 8: maxCredentialIdLength */
    if (wc_CBOR_EncodeUint(&c, 8) != 0) return -1;
    if (wc_CBOR_EncodeUint(&c, CRED_ID_LEN) != 0) return -1;

    /* 0x0A: algorithms, in Fidelio's order of preference (strongest first),
     * each as a PublicKeyCredentialParameters map. A relying party that
     * cares can read this instead of guessing.
     */
    {
        unsigned n = 0, i;
        while (cred_alg_at(n) != NULL)
            n++;
        if (wc_CBOR_EncodeUint(&c, 0x0A) != 0) return -1;
        if (wc_CBOR_EncodeArrayStart(&c, n) != 0) return -1;
        /* cred_alg_at() is ordered weakest-first; emit in reverse. */
        for (i = n; i > 0; i--) {
            const struct cred_alg *a = cred_alg_at(i - 1);
            if (wc_CBOR_EncodeMapStart(&c, 2) != 0) return -1;
            if (cbor_put_text(&c, "alg") != 0) return -1;
            if (wc_CBOR_EncodeInt(&c, a->cose) != 0) return -1;
            if (cbor_put_text(&c, "type") != 0) return -1;
            if (cbor_put_text(&c, "public-key") != 0) return -1;
        }
    }

    *reply_len = (uint16_t)c.idx;
    return 0;
}

static int ctap2_make_credential(const uint8_t *payload, uint16_t payload_len,
                                 uint8_t *reply, uint16_t reply_max, uint16_t *reply_len)
{
    struct mc_params params;
    const struct cred_alg *alg;
    struct cred_key user_key;
    uint8_t rpIdHash[HASH_SZ];
    static uint8_t authData[CRED_PUB_MAX + 256];
    uint16_t authDataLen = 0;
    uint8_t credId[CRED_ID_LEN];
    uint16_t credIdLen = 0;
    uint8_t signature[SIGMAX_SZ];
    word32 siglen = SIGMAX_SZ;
    uint8_t digest[HASH_SZ];
    wc_Sha256 sha;
    WC_RNG rng;
    ecc_key cert_ecc;
    int ret;

    memset(&user_key, 0, sizeof(user_key));

    if (parse_makecred(payload + 1, payload_len - 1, &params) != 0) {
        reply[0] = CTAP2_ERR_INVALID_CBOR;
        *reply_len = 1;
        return 0;
    }

    if (params.pin_protocol && params.pin_protocol != CTAP2_PIN_PROTOCOL_SUPPORTED) {
        reply[0] = CTAP2_ERR_INVALID_CBOR;
        *reply_len = 1;
        return 0;
    }

    pin_state_load();
    if (params.uv_required && pin_store.magic != FLASH_PIN_MAGIC) {
        reply[0] = CTAP2_ERR_PIN_NOT_SET;
        *reply_len = 1;
        return 0;
    }

    bool pin_verified = false;
    bool require_pin = params.uv_required || (params.pin_auth && params.pin_auth_len > 0);
    int pin_needed = pin_require_for_op(params.pin_auth, params.pin_auth_len,
                                        params.clientDataHash, params.cdh_len,
                                        require_pin, &pin_verified);
    if (pin_needed != 0) {
        reply[0] = (uint8_t)pin_needed;
        *reply_len = 1;
        return 0;
    }

    /* Pick the strongest algorithm the relying party is willing to accept.
     * WebAuthn states pubKeyCredParams in the RP's order of preference; this
     * deliberately overrides that in favour of the strongest mutually
     * supported option, which on this hardware also happens to be affordable
     * (ML-DSA-87 derive+sign worst case 513 ms at 125 MHz).
     */
    alg = cred_alg_best(params.alg_mask);
    if (alg == NULL) {
        reply[0] = CTAP2_ERR_UNSUPPORTED_ALGORITHM;
        *reply_len = 1;
        return 0;
    }

    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, params.rp_id, params.rp_id_len);
    wc_Sha256Final(&sha, rpIdHash);
    wc_Sha256Free(&sha);

    /* Require user presence */
    indicator_wait_for_button(0x0, 0x20, 0);

    if (wc_InitRng(&rng) != 0) {
        reply[0] = CTAP2_ERR_INVALID_COMMAND;
        *reply_len = 1;
        return 0;
    }

    if (build_credential_id(&rng, alg, rpIdHash, credId, sizeof(credId),
                            &credIdLen) != 0) {
        wc_FreeRng(&rng);
        reply[0] = CTAP2_ERR_INVALID_COMMAND;
        *reply_len = 1;
        return 0;
    }

    wc_ecc_init(&cert_ecc);

    word32 inOutIdx = 0;
    if (cred_alg_derive(alg, device_get_secret(), rpIdHash, credId + 1,
                        &user_key) != 0) {
        ret = -1; goto cleanup;
    }

    if (params.rk) {
        /* Discoverable credential: the relying party will later ask for it
         * without supplying a credential ID, so the mapping has to be kept.
         * It goes into the sealed vault, never plaintext flash. */
        struct cred_record rec;
        memset(&rec, 0, sizeof(rec));
        memcpy(rec.rp_id_hash, rpIdHash, HASH_SZ);
        memcpy(rec.cred_id, credId, credIdLen);
        rec.cred_id_len = (uint8_t)credIdLen;
        if (params.user_handle && params.user_handle_len > 0 &&
            params.user_handle_len <= sizeof(rec.user_id)) {
            memcpy(rec.user_id, params.user_handle, params.user_handle_len);
            rec.user_id_len = (uint8_t)params.user_handle_len;
        }
        if (params.user_name && params.user_name_len > 0) {
            uint32_t n = params.user_name_len;
            if (n > CRED_STORE_NAME_MAX)
                n = CRED_STORE_NAME_MAX;
            memcpy(rec.user_name, params.user_name, n);
            rec.user_name[n] = '\0';
        }
        if (cred_store_put(&rec) != 0) {
            ForceZero(&rec, sizeof(rec));
            ret = CTAP2_ERR_KEY_STORE_FULL; goto cleanup;
        }
        ForceZero(&rec, sizeof(rec));
    }

    if (wc_EccPrivateKeyDecode(cert_master_key_der, &inOutIdx, &cert_ecc, cert_master_key_der_len) != 0) {
        ret = -1; goto cleanup;
    }
    if (wc_ecc_check_key(&cert_ecc) != 0) {
        ret = -1; goto cleanup;
    }

    uint8_t flags = 0x41;
    if (pin_store.magic == FLASH_PIN_MAGIC && params.pin_auth && params.pin_auth_len == 16)
        flags |= 0x04;

    if (build_authdata_attested(rpIdHash, flags, CTAP2_SIGN_COUNT, credId, credIdLen, &user_key,
                                authData, sizeof(authData), &authDataLen) != 0) {
        ret = -1; goto cleanup;
    }

    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, authData, authDataLen);
    wc_Sha256Update(&sha, params.clientDataHash, params.cdh_len);
    wc_Sha256Final(&sha, digest);

    siglen = (word32)wc_ecc_sig_size(&cert_ecc);
    ret = wc_ecc_sign_hash(digest, HASH_SZ, signature, &siglen, &rng, &cert_ecc);
    wc_Sha256Free(&sha);
    if (ret != 0)
        goto cleanup;

    /* No signature counter to advance (see CTAP2_SIGN_COUNT), which also
     * keeps makeCredential off the flash entirely. */

    /* Build response */
    WOLFCOSE_CBOR_CTX c;
    cbor_enc_init(&c, reply, reply_max, 1);
    reply[0] = CTAP2_ERR_SUCCESS;
    if (wc_CBOR_EncodeMapStart(&c, 3) != 0) { ret = -1; goto cleanup; }
    if (wc_CBOR_EncodeUint(&c, 1) != 0) { ret = -1; goto cleanup; }
    if (cbor_put_text(&c, "packed") != 0) { ret = -1; goto cleanup; }
    if (wc_CBOR_EncodeUint(&c, 2) != 0) { ret = -1; goto cleanup; }
    if (wc_CBOR_EncodeBstr(&c, authData, authDataLen) != 0) { ret = -1; goto cleanup; }
    if (wc_CBOR_EncodeUint(&c, 3) != 0) { ret = -1; goto cleanup; }
    if (wc_CBOR_EncodeMapStart(&c, 3) != 0) { ret = -1; goto cleanup; }
    if (cbor_put_text(&c, "alg") != 0) { ret = -1; goto cleanup; }
    if (wc_CBOR_EncodeInt(&c, COSE_ALG_ES256) != 0) { ret = -1; goto cleanup; }
    if (cbor_put_text(&c, "sig") != 0) { ret = -1; goto cleanup; }
    if (wc_CBOR_EncodeBstr(&c, signature, (size_t)siglen) != 0) { ret = -1; goto cleanup; }
    if (cbor_put_text(&c, "x5c") != 0) { ret = -1; goto cleanup; }
    if (wc_CBOR_EncodeArrayStart(&c, 1) != 0) { ret = -1; goto cleanup; }
    if (wc_CBOR_EncodeBstr(&c, cert_att_der, cert_att_der_len) != 0) { ret = -1; goto cleanup; }

    *reply_len = (uint16_t)c.idx;
    ret = 0;

cleanup:
    wc_FreeRng(&rng);
    cred_key_free(&user_key);
    wc_ecc_free(&cert_ecc);
    ForceZero(digest, sizeof(digest));
    if (ret != 0) {
        reply[0] = CTAP2_ERR_INVALID_COMMAND;
        *reply_len = 1;
        return 0;
    }
    return 0;
}

static int ctap2_get_assertion(const uint8_t *payload, uint16_t payload_len,
                               uint8_t *reply, uint16_t reply_max, uint16_t *reply_len)
{
    struct ga_params params;
    struct cred_key user_key;
    uint8_t rpIdHash[HASH_SZ];
    static uint8_t authData[CRED_PUB_MAX + 256];
    uint16_t authDataLen = 0;
    uint8_t ext_buf[128];
    uint16_t ext_len = 0;
    static uint8_t sigbuf[CRED_SIG_MAX];
    static uint8_t signed_msg[CRED_PUB_MAX + 320];
    uint16_t siglen = sizeof(sigbuf);
    wc_Sha256 sha;
    WC_RNG rng;
    int ret = 0;

    memset(&user_key, 0, sizeof(user_key));

    if (parse_getassert(payload + 1, payload_len - 1, &params) != 0) {
        reply[0] = CTAP2_ERR_INVALID_CBOR;
        *reply_len = 1;
        return 0;
    }
    if (params.pin_protocol && params.pin_protocol != CTAP2_PIN_PROTOCOL_SUPPORTED) {
        reply[0] = CTAP2_ERR_INVALID_CBOR;
        *reply_len = 1;
        return 0;
    }

    pin_state_load();
    if (params.uv_required && pin_store.magic != FLASH_PIN_MAGIC) {
        reply[0] = CTAP2_ERR_PIN_NOT_SET;
        *reply_len = 1;
        return 0;
    }

    bool pin_verified = false;
    bool require_pin = params.uv_required || (params.pin_auth && params.pin_auth_len > 0);
    int pin_needed = pin_require_for_op(params.pin_auth, params.pin_auth_len,
                                        params.clientDataHash, params.cdh_len,
                                        require_pin, &pin_verified);
    if (pin_needed != 0) {
        reply[0] = (uint8_t)pin_needed;
        *reply_len = 1;
        return 0;
    }

    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, params.rp_id, params.rp_id_len);
    wc_Sha256Final(&sha, rpIdHash);
    wc_Sha256Free(&sha);

    /* Walk allowList entries until a matching handle is found. */
    uint32_t allow_off = 0;
    bool found = false;
    const struct cred_record *disc = NULL;
    unsigned disc_count = 0;

    /* No allowList: the relying party expects the authenticator to discover
     * the credential itself. That is the whole point of a resident key, and
     * the only case where Fidelio needs stored state. */
    if (params.allow_rk || (params.allow_list_len == 0 && !params.cred_id)) {
        disc_count = cred_store_count(rpIdHash);
        disc = cred_store_get(rpIdHash, 0);
        if (disc != NULL) {
            if (cred_open(disc->cred_id, disc->cred_id_len, rpIdHash,
                          &user_key, NULL) == 0) {
                params.cred_id = disc->cred_id;
                params.cred_id_len = disc->cred_id_len;
                found = true;
            }
        }
        if (!found) {
            reply[0] = CTAP2_ERR_NO_CREDENTIALS;
            *reply_len = 1;
            return 0;
        }
    }
    if (!found)
    do {
        const uint8_t *cid = params.cred_id;
        uint32_t cid_len = params.cred_id_len;
        if (params.allow_list_len > 0 && params.allow_list) {
            /* iterate over allowList */
            if (allow_off >= params.allow_list_len) {
                break;
            }
            /* Parse next descriptor */
            WOLFCOSE_CBOR_CTX ac;
            uint32_t mitems;
            const uint8_t *desc_id = NULL; uint32_t desc_id_len = 0;
            bool desc_ok = true;

            cbor_dec_init(&ac, params.allow_list + allow_off,
                          (uint16_t)(params.allow_list_len - allow_off));
            if (cbor_read_map(&ac, &mitems) != 0)
                break;
            for (uint32_t j = 0; j < mitems; j++) {
                struct cbor_key mkey;
                if (cbor_read_key(&ac, &mkey) != 0) {
                    desc_ok = false;
                    break;
                }
                if (cbor_key_is(&mkey, 1, "type")) {
                    const uint8_t *tv; uint32_t tvlen;
                    if (cbor_read_text(&ac, &tv, &tvlen) != 0) {
                        desc_ok = false;
                        break;
                    }
                } else if (cbor_key_is(&mkey, 2, "id")) {
                    if (cbor_read_bytes(&ac, &desc_id, &desc_id_len) != 0) {
                        desc_ok = false;
                        break;
                    }
                } else if (wc_CBOR_Skip(&ac) != WOLFCOSE_SUCCESS) {
                    desc_ok = false;
                    break;
                }
            }
            /* Advance past whatever was consumed; a malformed descriptor
             * ends the scan rather than looping on the same offset. */
            allow_off += (uint32_t)ac.idx;
            if (!desc_ok || ac.idx == 0)
                break;
            if (desc_id && desc_id_len > 0) {
                cid = desc_id;
                cid_len = desc_id_len;
            } else {
                continue;
            }
        }

        if (cid_len != CRED_ID_LEN) {
            continue;
        }
        /* Authenticates the credential ID and derives its key in one step;
         * a forged or foreign ID is rejected before any keygen runs. */
        if (cred_open(cid, (uint16_t)cid_len, rpIdHash, &user_key, NULL) != 0)
            continue;
        /* found matching cred */
        params.cred_id = cid;
        params.cred_id_len = cid_len;
        found = true;
        break;
    } while (params.allow_list_len > 0 && allow_off < params.allow_list_len);

    if (!found) {
        reply[0] = CTAP2_ERR_NO_CREDENTIALS;
        *reply_len = 1;
        return 0;
    }

    /* Require user presence */
    indicator_wait_for_button(0, 0, 0x20);

    if (wc_InitRng(&rng) != 0) {
        reply[0] = CTAP2_ERR_INVALID_COMMAND;
        *reply_len = 1;
        return 0;
    }

    uint8_t flags = 0x01;
    if (pin_verified)
        flags |= 0x04;

    if (params.hmac_secret_requested) {
        uint8_t shared[HASH_SZ * 2];
        uint8_t salt_dec[64];
        uint8_t hs_output[64];
        uint8_t mac[HASH_SZ];
        uint8_t cred_random[HASH_SZ];
        uint8_t iv[16] = {0};
        Aes aes;
        Hmac hmac;

        /* Every exit below, the error jumps included, must scrub these: they
         * hold the ECDH shared secret, the plaintext salts and the
         * per-credential seed. Previously only the success path did, so any
         * failure left them live on the stack for whatever ran next.
         */
        #define hs_fail(code) do { \
            ForceZero(shared, sizeof(shared)); \
            ForceZero(salt_dec, sizeof(salt_dec)); \
            ForceZero(hs_output, sizeof(hs_output)); \
            ForceZero(mac, sizeof(mac)); \
            ForceZero(cred_random, sizeof(cred_random)); \
            ret = (code); goto ga_cleanup; \
        } while (0)

        memset(shared, 0, sizeof(shared));
        memset(salt_dec, 0, sizeof(salt_dec));
        memset(hs_output, 0, sizeof(hs_output));
        memset(mac, 0, sizeof(mac));
        memset(cred_random, 0, sizeof(cred_random));

        if (!params.hmac_secret_valid) { hs_fail(CTAP2_ERR_INVALID_CBOR); }
        if (pin_shared_secret(params.hs_platform_qx, params.hs_platform_qy, shared) != 0) { hs_fail(CTAP2_ERR_PIN_AUTH_INVALID); }

        if (wc_HmacInit(&hmac, NULL, 0) != 0) { hs_fail(CTAP2_ERR_PIN_AUTH_INVALID); }
        if (wc_HmacSetKey(&hmac, SHA256, shared, HASH_SZ) != 0) { wc_HmacFree(&hmac); hs_fail(CTAP2_ERR_PIN_AUTH_INVALID); }
        wc_HmacUpdate(&hmac, params.hs_salt_enc, params.hs_salt_enc_len);
        wc_HmacFinal(&hmac, mac);
        wc_HmacFree(&hmac);
        if (!ct_memeq(mac, params.hs_salt_auth, 16)) { hs_fail(CTAP2_ERR_PIN_AUTH_INVALID); }

        if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) { hs_fail(CTAP2_ERR_PIN_AUTH_INVALID); }
        if (wc_AesSetKey(&aes, shared + HASH_SZ, 32, iv, AES_DECRYPTION) != 0) { wc_AesFree(&aes); hs_fail(CTAP2_ERR_PIN_AUTH_INVALID); }
        if (wc_AesCbcDecrypt(&aes, salt_dec, params.hs_salt_enc, params.hs_salt_enc_len) != 0) { wc_AesFree(&aes); hs_fail(CTAP2_ERR_PIN_AUTH_INVALID); }
        wc_AesFree(&aes);

        if (derive_cred_random(rpIdHash, params.cred_id, (uint16_t)params.cred_id_len, cred_random) != 0) { hs_fail(CTAP2_ERR_INVALID_COMMAND); }
        uint16_t salt_blocks = (uint16_t)(params.hs_salt_enc_len / 32);
        for (uint16_t i = 0; i < salt_blocks; i++) {
            if (wc_HmacInit(&hmac, NULL, 0) != 0) { hs_fail(CTAP2_ERR_INVALID_COMMAND); }
            if (wc_HmacSetKey(&hmac, SHA256, cred_random, HASH_SZ) != 0) { wc_HmacFree(&hmac); hs_fail(CTAP2_ERR_INVALID_COMMAND); }
            wc_HmacUpdate(&hmac, salt_dec + (i * 32), 32);
            wc_HmacFinal(&hmac, hs_output + (i * 32));
            wc_HmacFree(&hmac);
        }

        if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) { hs_fail(CTAP2_ERR_INVALID_COMMAND); }
        memset(iv, 0, sizeof(iv));
        if (wc_AesSetKey(&aes, shared + HASH_SZ, 32, iv, AES_ENCRYPTION) != 0) { wc_AesFree(&aes); hs_fail(CTAP2_ERR_INVALID_COMMAND); }
        if (wc_AesCbcEncrypt(&aes, salt_dec, hs_output, params.hs_salt_enc_len) != 0) { wc_AesFree(&aes); hs_fail(CTAP2_ERR_INVALID_COMMAND); }
        wc_AesFree(&aes);

        WOLFCOSE_CBOR_CTX ext;
        cbor_enc_init(&ext, ext_buf, sizeof(ext_buf), 0);
        if (wc_CBOR_EncodeMapStart(&ext, 1) != 0) { hs_fail(CTAP2_ERR_INVALID_COMMAND); }
        if (cbor_put_text(&ext, "hmac-secret") != 0) { hs_fail(CTAP2_ERR_INVALID_COMMAND); }
        if (wc_CBOR_EncodeBstr(&ext, salt_dec, params.hs_salt_enc_len) != 0) { hs_fail(CTAP2_ERR_INVALID_COMMAND); }
        ext_len = (uint16_t)ext.idx;
        ForceZero(shared, sizeof(shared));
        ForceZero(mac, sizeof(mac));
        ForceZero(cred_random, sizeof(cred_random));
        ForceZero(hs_output, sizeof(hs_output));
        ForceZero(salt_dec, sizeof(salt_dec));
        #undef hs_fail
    }

    if (build_authdata_assert(rpIdHash, flags, CTAP2_SIGN_COUNT,
                              ext_len ? ext_buf : NULL, ext_len,
                              authData, sizeof(authData), &authDataLen) != 0) {
        ret = -1; goto ga_cleanup;
    }

    /* WebAuthn signs authData || clientDataHash. Each algorithm applies its
     * own hashing inside cred_alg_sign(): ECDSA pre-hashes, EdDSA and ML-DSA
     * take the message directly, so the concatenation is passed whole.
     */
    if ((uint32_t)authDataLen + params.cdh_len > sizeof(signed_msg)) {
        ret = -1; goto ga_cleanup;
    }
    memcpy(signed_msg, authData, authDataLen);
    memcpy(signed_msg + authDataLen, params.clientDataHash, params.cdh_len);
    siglen = sizeof(sigbuf);
    if (cred_alg_sign(&user_key, signed_msg,
                      (uint16_t)(authDataLen + params.cdh_len),
                      sigbuf, &siglen, &rng) != 0) {
        ret = -1; goto ga_cleanup;
    }

    /* No signature counter to advance (see CTAP2_SIGN_COUNT). */

    WOLFCOSE_CBOR_CTX c;
    cbor_enc_init(&c, reply, reply_max, 1);
    reply[0] = CTAP2_ERR_SUCCESS;
    /* A discoverable assertion additionally returns the user entity (4) so
     * the relying party knows which account signed in. */
    if (wc_CBOR_EncodeMapStart(&c, disc ? 5 : 4) != 0) { ret = -1; goto ga_cleanup; }
    if (wc_CBOR_EncodeUint(&c, 1) != 0) { ret = -1; goto ga_cleanup; }
    if (wc_CBOR_EncodeMapStart(&c, 2) != 0) { ret = -1; goto ga_cleanup; }
    if (cbor_put_text(&c, "id") != 0) { ret = -1; goto ga_cleanup; }
    if (wc_CBOR_EncodeBstr(&c, params.cred_id, params.cred_id_len) != 0) { ret = -1; goto ga_cleanup; }
    if (cbor_put_text(&c, "type") != 0) { ret = -1; goto ga_cleanup; }
    if (cbor_put_text(&c, "public-key") != 0) { ret = -1; goto ga_cleanup; }

    if (wc_CBOR_EncodeUint(&c, 2) != 0) { ret = -1; goto ga_cleanup; }
    if (wc_CBOR_EncodeBstr(&c, authData, authDataLen) != 0) { ret = -1; goto ga_cleanup; }
    if (wc_CBOR_EncodeUint(&c, 3) != 0) { ret = -1; goto ga_cleanup; }
    if (wc_CBOR_EncodeBstr(&c, sigbuf, (size_t)siglen) != 0) { ret = -1; goto ga_cleanup; }
    if (disc != NULL) {
        if (wc_CBOR_EncodeUint(&c, 4) != 0) { ret = -1; goto ga_cleanup; }
        if (wc_CBOR_EncodeMapStart(&c, disc->user_name[0] ? 2 : 1) != 0) { ret = -1; goto ga_cleanup; }
        if (cbor_put_text(&c, "id") != 0) { ret = -1; goto ga_cleanup; }
        if (wc_CBOR_EncodeBstr(&c, disc->user_id, disc->user_id_len) != 0) { ret = -1; goto ga_cleanup; }
        if (disc->user_name[0]) {
            if (cbor_put_text(&c, "name") != 0) { ret = -1; goto ga_cleanup; }
            if (cbor_put_text(&c, disc->user_name) != 0) { ret = -1; goto ga_cleanup; }
        }
    }
    if (wc_CBOR_EncodeUint(&c, 5) != 0) { ret = -1; goto ga_cleanup; }
    if (wc_CBOR_EncodeUint(&c, disc ? disc_count : 1) != 0) { ret = -1; goto ga_cleanup; }

    *reply_len = (uint16_t)c.idx;

ga_cleanup:
    wc_FreeRng(&rng);
    cred_key_free(&user_key);
    if (ret != 0) {
        reply[0] = (ret > 0) ? (uint8_t)ret : CTAP2_ERR_NO_CREDENTIALS;
        *reply_len = 1;
    }
    return 0;
}

/* The clientPIN handler has around twenty exit paths, and these hold the
 * ECDH shared secret and the decrypted PIN. Keeping them at file scope lets
 * the wrapper below scrub them on every one of those paths, including the
 * error returns, rather than relying on each to remember.
 */
static uint8_t pin_shared[HASH_SZ * 2]; /* 32-byte HMAC key + 32-byte AES key */
static uint8_t pin_tmp[64];

static int ctap2_client_pin_inner(const uint8_t *payload, uint16_t payload_len,
                            uint8_t *reply, uint16_t reply_max, uint16_t *reply_len)
{
    WOLFCOSE_CBOR_CTX c;
    uint32_t items;
    uint32_t pinProtocol = 0, subCmd = 0;
    const uint8_t *key_agree = NULL; uint16_t key_agree_len = 0;
    const uint8_t *pin_auth = NULL; uint32_t pin_auth_len = 0;
    const uint8_t *newPinEnc = NULL; uint32_t newPinEnc_len = 0;
    const uint8_t *pinHashEnc = NULL; uint32_t pinHashEnc_len = 0;
    uint8_t platform_qx[ECC_SZ], platform_qy[ECC_SZ];
    Hmac hmac;
    WC_RNG rng;
    int ret = 0;

    pin_state_load();

    cbor_dec_init(&c, payload + 1, (uint16_t)(payload_len - 1));
    if (cbor_read_map(&c, &items) != 0)
        return -1;
    for (uint32_t i = 0; i < items; i++) {
        uint64_t key;
        if (wc_CBOR_DecodeUint(&c, &key) != WOLFCOSE_SUCCESS)
            return -1;
        switch (key) {
            case 1: { /* pinProtocol */
                uint64_t v;
                if (wc_CBOR_DecodeUint(&c, &v) != WOLFCOSE_SUCCESS)
                    return -1;
                pinProtocol = (uint32_t)v;
                break;
            }
            case 2: { /* subCmd */
                uint64_t v;
                if (wc_CBOR_DecodeUint(&c, &v) != WOLFCOSE_SUCCESS)
                    return -1;
                subCmd = (uint32_t)v;
                break;
            }
            case 3: /* keyAgreement */
                if (cbor_skip_slice(&c, &key_agree, &key_agree_len) != 0)
                    return -1;
                break;
            case 4: /* pinAuth */
                if (cbor_read_bytes(&c, &pin_auth, &pin_auth_len) != 0)
                    return -1;
                break;
            case 5: /* newPinEnc */
                if (cbor_read_bytes(&c, &newPinEnc, &newPinEnc_len) != 0)
                    return -1;
                break;
            case 6: /* pinHashEnc */
                if (cbor_read_bytes(&c, &pinHashEnc, &pinHashEnc_len) != 0)
                    return -1;
                break;
            default:
                if (wc_CBOR_Skip(&c) != WOLFCOSE_SUCCESS)
                    return -1;
                break;
        }
    }

    if (pinProtocol != CTAP2_PIN_PROTOCOL_SUPPORTED) {
        reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0;
    }

    switch (subCmd) {
        case 1: { /* getRetries */
            WOLFCOSE_CBOR_CTX rc;
            cbor_enc_init(&rc, reply, reply_max, 1);
            reply[0] = CTAP2_ERR_SUCCESS;
            if (wc_CBOR_EncodeMapStart(&rc, 1) != 0) return -1;
            if (wc_CBOR_EncodeUint(&rc, 3) != 0) return -1; /* PIN_RETRIES */
            if (wc_CBOR_EncodeUint(&rc, pin_store.retries) != 0) return -1;
            *reply_len = (uint16_t)rc.idx;
            return 0;
        }
        case 2: { /* getKeyAgreement */
            WOLFCOSE_CBOR_CTX rc;
            wc_InitRng(&rng);
            if (pin_generate_agreement_key(&rng) != 0) {
                wc_FreeRng(&rng);
                reply[0] = CTAP2_ERR_INVALID_COMMAND; *reply_len = 1; return 0;
            }
            wc_FreeRng(&rng);
            cbor_enc_init(&rc, reply, reply_max, 1);
            reply[0] = CTAP2_ERR_SUCCESS;
            if (wc_CBOR_EncodeMapStart(&rc, 1) != 0) return -1;
            if (wc_CBOR_EncodeUint(&rc, 1) != 0) return -1;
            if (encode_cose_pubkey(&rc, &pin_agree_key,
                                   COSE_ALG_ECDH_ES_HKDF256) != 0) return -1;
            *reply_len = (uint16_t)rc.idx;
            return 0;
        }
        case 3: { /* setPIN */
            if (pin_store.magic == FLASH_PIN_MAGIC) {
                reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0;
            }
            if (!key_agree || !pin_agree_valid || parse_cose_pubkey(key_agree, key_agree_len, platform_qx, platform_qy) != 0) {
                reply[0] = CTAP2_ERR_INVALID_CBOR; *reply_len = 1; return 0;
            }
            if (!pin_auth || pin_auth_len != 16 || !newPinEnc || newPinEnc_len != 64) {
                reply[0] = CTAP2_ERR_INVALID_LENGTH; *reply_len = 1; return 0;
            }
            if (pin_shared_secret(platform_qx, platform_qy, pin_shared) != 0) {
                reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0;
            }
            /* pinAuth = LEFT(HMAC(sharedSecret[0:32], newPinEnc), 16) */
            if (wc_HmacInit(&hmac, NULL, 0) != 0) { return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len); }
            if (wc_HmacSetKey(&hmac, SHA256, pin_shared, HASH_SZ) != 0) { wc_HmacFree(&hmac); return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len); }
            wc_HmacUpdate(&hmac, newPinEnc, newPinEnc_len);
            wc_HmacFinal(&hmac, pin_tmp);
            wc_HmacFree(&hmac);
            if (!ct_memeq(pin_tmp, pin_auth, 16)) {
                reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0;
            }
            /* newPinEnc: AES-256-CBC(sharedSecret[32:], iv=0, padded PIN, 64 bytes) */
            {
                Aes aes;
                uint8_t iv[16] = {0};
                if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) { reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0; }
                if (wc_AesSetKey(&aes, pin_shared + 32, 32, iv, AES_DECRYPTION) != 0) { wc_AesFree(&aes); reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0; }
                if (wc_AesCbcDecrypt(&aes, pin_tmp, newPinEnc, newPinEnc_len) != 0) { wc_AesFree(&aes); reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0; }
                wc_AesFree(&aes);
            }
            /* derive hash */
            uint16_t pin_len = 0;
            for (int i = 0; i < 64; i++) {
                if (pin_tmp[i] == 0) { pin_len = (uint16_t)i; break; }
            }
            if (pin_len == 0) pin_len = 64;
            if (pin_hash_plain(pin_tmp, pin_len, pin_store.pin_hash) != 0) {
                reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0;
            }
            pin_restore_retries();
            wc_InitRng(&rng);
            pin_reset_token(&rng);
            wc_FreeRng(&rng);
            WOLFCOSE_CBOR_CTX rc;
            cbor_enc_init(&rc, reply, reply_max, 1);
            reply[0] = CTAP2_ERR_SUCCESS;
            if (wc_CBOR_EncodeMapStart(&rc, 0) != 0) return -1;
            *reply_len = (uint16_t)rc.idx;
            return 0;
        }
        case 4: { /* changePIN */
            if (pin_store.magic != FLASH_PIN_MAGIC) {
                reply[0] = CTAP2_ERR_PIN_NOT_SET; *reply_len = 1; return 0;
            }
            if (pin_spend_retry() != 0) {
                reply[0] = CTAP2_ERR_PIN_BLOCKED; *reply_len = 1; return 0;
            }
            if (!key_agree || !pin_agree_valid || parse_cose_pubkey(key_agree, key_agree_len, platform_qx, platform_qy) != 0) {
                reply[0] = CTAP2_ERR_INVALID_CBOR; *reply_len = 1; return 0;
            }
            if (!pin_auth || pin_auth_len != 16 || !newPinEnc || newPinEnc_len != 64 || !pinHashEnc || pinHashEnc_len != 16) {
                reply[0] = CTAP2_ERR_INVALID_LENGTH; *reply_len = 1; return 0;
            }
            if (pin_shared_secret(platform_qx, platform_qy, pin_shared) != 0) {
                return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len);
            }
            /* pinHashEnc: AES-256-CBC(sharedSecret[32:], iv=0, LEFT(SHA256(PIN),16)) */
            {
                Aes aes;
                uint8_t iv[16] = {0};
                if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) { return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len); }
                if (wc_AesSetKey(&aes, pin_shared + 32, 32, iv, AES_DECRYPTION) != 0) { wc_AesFree(&aes); return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len); }
                if (wc_AesCbcDecrypt(&aes, pin_tmp, pinHashEnc, pinHashEnc_len) != 0) { wc_AesFree(&aes); return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len); }
                wc_AesFree(&aes);
            }
            if (!ct_memeq(pin_tmp, pin_store.pin_hash, 16)) {
                ForceZero(pin_tmp, sizeof(pin_tmp));
                ForceZero(pin_shared, sizeof(pin_shared));
                reply[0] = CTAP2_ERR_PIN_INVALID; *reply_len = 1; return 0;
            }
            if (wc_HmacInit(&hmac, NULL, 0) != 0) { return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len); }
            if (wc_HmacSetKey(&hmac, SHA256, pin_shared, HASH_SZ) != 0) { wc_HmacFree(&hmac); return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len); }
            wc_HmacUpdate(&hmac, newPinEnc, newPinEnc_len);
            /* For changePIN, the auth covers both the new PIN and the old hash */
            wc_HmacUpdate(&hmac, pinHashEnc, pinHashEnc_len);
            wc_HmacFinal(&hmac, pin_tmp);
            wc_HmacFree(&hmac);
            if (!ct_memeq(pin_tmp, pin_auth, 16)) {
                ForceZero(pin_tmp, sizeof(pin_tmp));
                ForceZero(pin_shared, sizeof(pin_shared));
                return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len);
            }
            /* Decrypt newPinEnc (IV=0) */
            {
                Aes aes;
                uint8_t iv[16] = {0};
                if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) { return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len); }
                if (wc_AesSetKey(&aes, pin_shared + 32, 32, iv, AES_DECRYPTION) != 0) { wc_AesFree(&aes); return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len); }
                if (wc_AesCbcDecrypt(&aes, pin_tmp, newPinEnc, newPinEnc_len) != 0) { wc_AesFree(&aes); return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len); }
                wc_AesFree(&aes);
            }
            uint16_t pin_len = 0;
            for (int i = 0; i < 64; i++) {
                if (pin_tmp[i] == 0) { pin_len = (uint16_t)i; break; }
            }
            if (pin_len == 0) pin_len = 64;
            if (pin_hash_plain(pin_tmp, pin_len, pin_store.pin_hash) != 0) {
                reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0;
            }
            pin_restore_retries();
            wc_InitRng(&rng);
            pin_reset_token(&rng);
            wc_FreeRng(&rng);
            WOLFCOSE_CBOR_CTX rc;
            cbor_enc_init(&rc, reply, reply_max, 1);
            reply[0] = CTAP2_ERR_SUCCESS;
            if (wc_CBOR_EncodeMapStart(&rc, 0) != 0) return -1;
            *reply_len = (uint16_t)rc.idx;
            return 0;
        }
        case 5: { /* getPINToken */
            if (pin_store.magic != FLASH_PIN_MAGIC) {
                reply[0] = CTAP2_ERR_PIN_NOT_SET; *reply_len = 1; return 0;
            }
            if (pin_spend_retry() != 0) {
                reply[0] = CTAP2_ERR_PIN_BLOCKED; *reply_len = 1; return 0;
            }
            if (!key_agree || !pin_agree_valid || parse_cose_pubkey(key_agree, key_agree_len, platform_qx, platform_qy) != 0) {
                reply[0] = CTAP2_ERR_INVALID_CBOR; *reply_len = 1; return 0;
            }
            if (!pinHashEnc || pinHashEnc_len != 16) {
                reply[0] = CTAP2_ERR_INVALID_LENGTH; *reply_len = 1; return 0;
            }
            if (pin_shared_secret(platform_qx, platform_qy, pin_shared) != 0) {
                reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0;
            }
            /* pinHashEnc for protocol 1 is a single AES block with IV=0. */
            {
                Aes aes;
                uint8_t iv[16] = {0};
                if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) { reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0; }
                if (wc_AesSetKey(&aes, pin_shared + 32, 32, iv, AES_DECRYPTION) != 0) { wc_AesFree(&aes); reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0; }
                if (wc_AesCbcDecrypt(&aes, pin_tmp, pinHashEnc, pinHashEnc_len) != 0) { wc_AesFree(&aes); reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0; }
                wc_AesFree(&aes);
            }
            if (!ct_memeq(pin_tmp, pin_store.pin_hash, 16)) {
                ForceZero(pin_tmp, sizeof(pin_tmp));
                ForceZero(pin_shared, sizeof(pin_shared));
                reply[0] = CTAP2_ERR_PIN_INVALID; *reply_len = 1; return 0;
            }
            wc_InitRng(&rng);
            pin_reset_token(&rng);
            pin_restore_retries();
            /* Encrypt pinToken with AES-256-CBC, IV=0, no IV prefix (protocol 1). */
            {
                Aes aes;
                uint8_t iv[16] = {0};
                uint16_t enc_len = sizeof(pin_token);
                if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) { wc_FreeRng(&rng); reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0; }
                if (wc_AesSetKey(&aes, pin_shared + 32, 32, iv, AES_ENCRYPTION) != 0) { wc_AesFree(&aes); wc_FreeRng(&rng); reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0; }
                if (wc_AesCbcEncrypt(&aes, pin_tmp, pin_token, sizeof(pin_token)) != 0) { wc_AesFree(&aes); wc_FreeRng(&rng); reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0; }
                wc_AesFree(&aes);
                WOLFCOSE_CBOR_CTX rc;
                cbor_enc_init(&rc, reply, reply_max, 1);
                reply[0] = CTAP2_ERR_SUCCESS;
                if (wc_CBOR_EncodeMapStart(&rc, 1) != 0) { wc_FreeRng(&rng); return -1; }
                if (wc_CBOR_EncodeUint(&rc, 2) != 0) { wc_FreeRng(&rng); return -1; }
                if (wc_CBOR_EncodeBstr(&rc, pin_tmp, enc_len) != 0) { wc_FreeRng(&rng); return -1; }
                *reply_len = (uint16_t)rc.idx;
                wc_FreeRng(&rng);
                return 0;
            }
        }
        default:
            reply[0] = CTAP2_ERR_INVALID_COMMAND;
            *reply_len = 1;
            return 0;
    }
}

static int ctap2_client_pin(const uint8_t *payload, uint16_t payload_len,
                            uint8_t *reply, uint16_t reply_max,
                            uint16_t *reply_len)
{
    int ret = ctap2_client_pin_inner(payload, payload_len, reply, reply_max,
                                     reply_len);
    ForceZero(pin_shared, sizeof(pin_shared));
    ForceZero(pin_tmp, sizeof(pin_tmp));
    return ret;
}

void ctap2_reset_state(void)
{
    pin_state_reset();
    cred_store_wipe();
    fdo_reset();
}

int ctap2_handle_cbor(const uint8_t *payload, uint16_t payload_len,
                      uint8_t *reply, uint16_t reply_max, uint16_t *reply_len)
{
    if (payload_len == 0 || reply_max < 1)
        return -1;

    uint8_t cmd = payload[0];
    switch (cmd) {
        case CTAP2_CMD_MAKE_CREDENTIAL:
            return ctap2_make_credential(payload, payload_len, reply, reply_max, reply_len);
        case CTAP2_CMD_GET_ASSERTION:
            return ctap2_get_assertion(payload, payload_len, reply, reply_max, reply_len);
        case CTAP2_CMD_GET_INFO:
            return ctap2_write_getinfo(reply, reply_max, reply_len);
        case CTAP2_CMD_CLIENT_PIN:
            return ctap2_client_pin(payload, payload_len, reply, reply_max, reply_len);
        case CTAP2_CMD_RESET:
            pin_state_reset();
            cred_store_wipe();
            fdo_init();
            reply[0] = CTAP2_ERR_SUCCESS;
            *reply_len = 1;
            return 0;
        default:
            reply[0] = CTAP2_ERR_INVALID_COMMAND;
            *reply_len = 1;
            return 0;
    }
}
