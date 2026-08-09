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
#include "pico/stdlib.h"
#include "hardware/gpio.h"
#include "hardware/flash.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "fdo.h"
#include "indicator.h"
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
struct pin_state {
    uint32_t magic;
    uint8_t pin_hash[HASH_SZ];
    uint8_t retries;
    uint8_t reserved[3];
};

static struct pin_state pin_store;
static bool pin_loaded = false;
static bool pin_token_valid = false;
static uint8_t pin_token[32];

static ecc_key pin_agree_key;
static uint8_t pin_agree_qx[ECC_SZ];
static uint8_t pin_agree_qy[ECC_SZ];
static bool pin_agree_valid = false;
static bool pin_agree_consumed = true;

struct rk_slot {
    uint8_t magic[4];
    uint8_t rpIdHash[HASH_SZ];
    uint8_t user_handle[32];
    uint8_t cred_id[NONCE_SZ + HASH_SZ];
    uint16_t cred_id_len;
    uint8_t pub_qx[ECC_SZ];
    uint8_t pub_qy[ECC_SZ];
    uint32_t counter;
};

static struct rk_slot rk_slots[RK_MAX_SLOTS];
static bool rk_loaded = false;

static void rk_load(void)
{
    if (rk_loaded)
        return;
    const struct rk_slot *flash_rk = (const struct rk_slot *)(XIP_BASE + FLASH_RK_OFF);
    memcpy(rk_slots, flash_rk, sizeof(rk_slots));
    rk_loaded = true;
}

static void rk_save(void)
{
    flash_range_erase(FLASH_RK_OFF, FLASH_SECTOR_SIZE);
    flash_range_program(FLASH_RK_OFF, (const uint8_t *)rk_slots, sizeof(rk_slots));
}

static int rk_find_free(void)
{
    for (int i = 0; i < RK_MAX_SLOTS; i++) {
        if (memcmp(rk_slots[i].magic, (uint8_t[4]){0}, 4) == 0)
            return i;
    }
    return -1;
}

static int rk_find_match(const uint8_t *rpIdHash, const uint8_t *cred_id, uint16_t cred_len)
{
    for (int i = 0; i < RK_MAX_SLOTS; i++) {
        if (memcmp(rk_slots[i].magic, (uint8_t[4]){ 'R','K','!','!' }, 4) != 0)
            continue;
        if (rk_slots[i].cred_id_len == cred_len &&
            memcmp(rk_slots[i].rpIdHash, rpIdHash, HASH_SZ) == 0 &&
            memcmp(rk_slots[i].cred_id, cred_id, cred_len) == 0)
            return i;
    }
    return -1;
}

static int rk_find_first_for_rp(const uint8_t *rpIdHash)
{
    for (int i = 0; i < RK_MAX_SLOTS; i++) {
        if (memcmp(rk_slots[i].magic, (uint8_t[4]){ 'R','K','!','!' }, 4) != 0)
            continue;
        if (memcmp(rk_slots[i].rpIdHash, rpIdHash, HASH_SZ) == 0)
            return i;
    }
    return -1;
}

static void pin_state_reset(void)
{
    memset(&pin_store, 0, sizeof(pin_store));
    pin_loaded = false;
    pin_token_valid = false;
    pin_agree_valid = false;
    pin_agree_consumed = true;
    flash_range_erase(FLASH_PIN_OFF, FLASH_SECTOR_SIZE);
}

static void rk_reset(void)
{
    memset(rk_slots, 0, sizeof(rk_slots));
    rk_loaded = false;
    flash_range_erase(FLASH_RK_OFF, FLASH_SECTOR_SIZE);
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
    flash_range_erase(FLASH_PIN_OFF, FLASH_SECTOR_SIZE);
    flash_range_program(FLASH_PIN_OFF, (const uint8_t *)&pin_store, sizeof(pin_store));
}

static void pin_reset_token(WC_RNG *rng)
{
    wc_RNG_GenerateBlock(rng, pin_token, sizeof(pin_token));
    pin_token_valid = true;
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

static int pin_check_retries(void)
{
    pin_state_load();
    if (pin_store.retries == 0)
        return -1;
    return 0;
}

static void pin_fail_retry(void)
{
    if (pin_store.retries > 0) {
        pin_store.retries--;
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
    if (memcmp(mac, pin_auth, 16) != 0) {
        pin_fail_retry();
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if (verified)
        *verified = true;
    return 0;
}
static int derive_user_key(const uint8_t *rpIdHash, const uint8_t *nonce,
                           uint8_t *private_out, uint8_t *handle_hash)
{
    Hmac hmac;
    int ret;
    const uint8_t *secret = device_get_secret();

    ret = wc_HmacInit(&hmac, NULL, 0);
    if (ret != 0)
        return ret;
    ret = wc_HmacSetKey(&hmac, SHA256, secret, ECC_SZ);
    if (ret != 0)
        return ret;
    wc_HmacUpdate(&hmac, rpIdHash, HASH_SZ);
    wc_HmacUpdate(&hmac, nonce, NONCE_SZ);
    wc_HmacFinal(&hmac, private_out);
    wc_HmacFree(&hmac);

    ret = wc_HmacInit(&hmac, NULL, 0);
    if (ret != 0)
        return ret;
    ret = wc_HmacSetKey(&hmac, SHA256, secret, ECC_SZ);
    if (ret != 0)
        return ret;
    wc_HmacUpdate(&hmac, rpIdHash, HASH_SZ);
    wc_HmacUpdate(&hmac, private_out, ECC_SZ);
    wc_HmacFinal(&hmac, handle_hash);
    wc_HmacFree(&hmac);

    return 0;
}

static int derive_cred_random(const uint8_t *rpIdHash, const uint8_t *credId, uint16_t credIdLen,
                              const uint8_t *priv_key, uint8_t *cred_random)
{
    Hmac hmac;
    if (wc_HmacInit(&hmac, NULL, 0) != 0)
        return -1;
    if (wc_HmacSetKey(&hmac, SHA256, priv_key, ECC_SZ) != 0) {
        wc_HmacFree(&hmac);
        return -1;
    }
    wc_HmacUpdate(&hmac, rpIdHash, HASH_SZ);
    wc_HmacUpdate(&hmac, credId, credIdLen);
    wc_HmacFinal(&hmac, cred_random);
    wc_HmacFree(&hmac);
    return 0;
}

static int build_credential_id(WC_RNG *rng, const uint8_t *rpIdHash,
                               uint8_t *credId, uint16_t credIdCap, uint16_t *credIdLen,
                               uint8_t *user_private)
{
    uint8_t nonce[NONCE_SZ];
    uint8_t handle_hash[HASH_SZ];
    if (credIdCap < (NONCE_SZ + HASH_SZ))
        return -1;
    if (wc_RNG_GenerateBlock(rng, nonce, NONCE_SZ) != 0)
        return -1;
    if (derive_user_key(rpIdHash, nonce, user_private, handle_hash) != 0)
        return -1;
    memcpy(credId, nonce, NONCE_SZ);
    memcpy(credId + NONCE_SZ, handle_hash, HASH_SZ);
    *credIdLen = NONCE_SZ + HASH_SZ;
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
                                   ecc_key *pubkey,
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
    if (encode_cose_pubkey(&cose, pubkey, COSE_ALG_ES256) != 0)
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
    bool es256_ok;
    bool uv_required;
    const uint8_t *pin_auth;
    uint32_t pin_auth_len;
    int pin_protocol;
    const uint8_t *user_handle;
    uint32_t user_handle_len;
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
            case 4: { /* pubKeyCredParams */
                uint32_t acount;
                if (cbor_read_array(&c, &acount) != 0)
                    return -1;
                for (uint32_t j = 0; j < acount; j++) {
                    uint32_t mitems;
                    bool type_ok = false;
                    bool alg_ok = false;
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
                            if (aval == COSE_ALG_ES256)
                                alg_ok = true;
                        } else if (wc_CBOR_Skip(&c) != WOLFCOSE_SUCCESS) {
                            return -1;
                        }
                    }
                    if (type_ok && alg_ok)
                        out->es256_ok = true;
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
    if (!out->es256_ok)
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
    if (!out->allow_rk && (!out->cred_id || out->cred_id_len == 0) && out->allow_list_len == 0)
        return -1;
    return 0;
}

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
    if (cbor_put_bool(&c, false) != 0) return -1;
    if (cbor_put_text(&c, "up") != 0) return -1;
    if (cbor_put_bool(&c, true) != 0) return -1;
    if (cbor_put_text(&c, "uv") != 0) return -1;
    if (cbor_put_bool(&c, false) != 0) return -1;
    if (cbor_put_text(&c, "clientPin") != 0) return -1;
    if (cbor_put_bool(&c, true) != 0) return -1;

    /* 5: maxMsgSize */
    if (wc_CBOR_EncodeUint(&c, 5) != 0) return -1;
    if (wc_CBOR_EncodeUint(&c, 1024) != 0) return -1;

    /* 6: pinProtocols */
    if (wc_CBOR_EncodeUint(&c, 6) != 0) return -1;
    if (wc_CBOR_EncodeArrayStart(&c, 1) != 0) return -1;
    if (wc_CBOR_EncodeUint(&c, CTAP2_PIN_PROTOCOL_SUPPORTED) != 0) return -1;

    /* 7: maxCredentialCountInList */
    if (wc_CBOR_EncodeUint(&c, 7) != 0) return -1;
    if (wc_CBOR_EncodeUint(&c, 8) != 0) return -1;

    /* 8: maxCredentialIdLength */
    if (wc_CBOR_EncodeUint(&c, 8) != 0) return -1;
    if (wc_CBOR_EncodeUint(&c, 128) != 0) return -1;

    /* (algorithms omitted for now; add back when stable) */

    *reply_len = (uint16_t)c.idx;
    return 0;
}

static int ctap2_make_credential(const uint8_t *payload, uint16_t payload_len,
                                 uint8_t *reply, uint16_t reply_max, uint16_t *reply_len)
{
    struct mc_params params;
    uint8_t rpIdHash[HASH_SZ];
    uint8_t authData[256];
    uint16_t authDataLen = 0;
    uint8_t credId[NONCE_SZ + HASH_SZ];
    uint16_t credIdLen = 0;
    uint8_t signature[SIGMAX_SZ];
    word32 siglen = SIGMAX_SZ;
    uint8_t digest[HASH_SZ];
    uint8_t user_private[ECC_SZ];
    uint8_t qx[ECC_SZ], qy[ECC_SZ];
    wc_Sha256 sha;
    WC_RNG rng;
    ecc_key user_ecc;
    ecc_key cert_ecc;
    int ret;

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

    if (build_credential_id(&rng, rpIdHash, credId, sizeof(credId), &credIdLen, user_private) != 0) {
        wc_FreeRng(&rng);
        reply[0] = CTAP2_ERR_INVALID_COMMAND;
        *reply_len = 1;
        return 0;
    }

    wc_ecc_init(&user_ecc);
    wc_ecc_init(&cert_ecc);

    word32 inOutIdx = 0;
    if (wc_ecc_import_private_key_ex(user_private, ECC_SZ, NULL, 0, &user_ecc, ECC_SECP256R1) != 0) {
        ret = -1; goto cleanup;
    }
    if (wc_ecc_make_pub_ex(&user_ecc, NULL, NULL) != 0) {
        ret = -1; goto cleanup;
    }

    word32 qxlen = ECC_SZ, qylen = ECC_SZ;
    if (wc_ecc_export_public_raw(&user_ecc, qx, &qxlen, qy, &qylen) != 0) {
        ret = -1; goto cleanup;
    }

    rk_load();
    if (params.rk) {
        int slot = rk_find_free();
        if (slot >= 0) {
            memcpy(rk_slots[slot].magic, "RK!!", 4);
            memcpy(rk_slots[slot].rpIdHash, rpIdHash, HASH_SZ);
            rk_slots[slot].cred_id_len = credIdLen;
            memcpy(rk_slots[slot].cred_id, credId, credIdLen);
            rk_slots[slot].counter = device_get_counter();
            if (params.user_handle && params.user_handle_len <= sizeof(rk_slots[slot].user_handle))
                memcpy(rk_slots[slot].user_handle, params.user_handle, params.user_handle_len);
            memcpy(rk_slots[slot].pub_qx, qx, ECC_SZ);
            memcpy(rk_slots[slot].pub_qy, qy, ECC_SZ);
            rk_save();
        }
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

    if (build_authdata_attested(rpIdHash, flags, device_get_counter(), credId, credIdLen, &user_ecc,
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

    device_counter_inc();

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
    wc_ecc_free(&user_ecc);
    wc_ecc_free(&cert_ecc);
    ForceZero(user_private, sizeof(user_private));
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
    uint8_t rpIdHash[HASH_SZ];
    uint8_t private[ECC_SZ];
    uint8_t handle_hash[HASH_SZ];
    uint8_t authData[256];
    uint16_t authDataLen = 0;
    uint8_t ext_buf[128];
    uint16_t ext_len = 0;
    uint8_t sigbuf[SIGMAX_SZ];
    uint8_t digest[HASH_SZ];
    word32 siglen = SIGMAX_SZ;
    wc_Sha256 sha;
    ecc_key user_ecc;
    WC_RNG rng;
    int ret = 0;

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

        if (cid_len != (NONCE_SZ + HASH_SZ)) {
            continue;
        }
        if (derive_user_key(rpIdHash, cid, private, handle_hash) != 0)
            continue;
        if (memcmp(handle_hash, cid + NONCE_SZ, HASH_SZ) != 0)
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

    wc_ecc_init(&user_ecc);
    if (wc_ecc_import_private_key_ex(private, ECC_SZ, NULL, 0, &user_ecc, ECC_SECP256R1) != 0) {
        ret = -1; goto ga_cleanup;
    }
    if (wc_ecc_make_pub_ex(&user_ecc, NULL, NULL) != 0) {
        ret = -1; goto ga_cleanup;
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

        if (!params.hmac_secret_valid) { ret = CTAP2_ERR_INVALID_CBOR; goto ga_cleanup; }
        if (pin_shared_secret(params.hs_platform_qx, params.hs_platform_qy, shared) != 0) { ret = CTAP2_ERR_PIN_AUTH_INVALID; goto ga_cleanup; }

        if (wc_HmacInit(&hmac, NULL, 0) != 0) { ret = CTAP2_ERR_PIN_AUTH_INVALID; goto ga_cleanup; }
        if (wc_HmacSetKey(&hmac, SHA256, shared, HASH_SZ) != 0) { wc_HmacFree(&hmac); ret = CTAP2_ERR_PIN_AUTH_INVALID; goto ga_cleanup; }
        wc_HmacUpdate(&hmac, params.hs_salt_enc, params.hs_salt_enc_len);
        wc_HmacFinal(&hmac, mac);
        wc_HmacFree(&hmac);
        if (memcmp(mac, params.hs_salt_auth, 16) != 0) { ret = CTAP2_ERR_PIN_AUTH_INVALID; goto ga_cleanup; }

        if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) { ret = CTAP2_ERR_PIN_AUTH_INVALID; goto ga_cleanup; }
        if (wc_AesSetKey(&aes, shared + HASH_SZ, 32, iv, AES_DECRYPTION) != 0) { wc_AesFree(&aes); ret = CTAP2_ERR_PIN_AUTH_INVALID; goto ga_cleanup; }
        if (wc_AesCbcDecrypt(&aes, salt_dec, params.hs_salt_enc, params.hs_salt_enc_len) != 0) { wc_AesFree(&aes); ret = CTAP2_ERR_PIN_AUTH_INVALID; goto ga_cleanup; }
        wc_AesFree(&aes);

        if (derive_cred_random(rpIdHash, params.cred_id, (uint16_t)params.cred_id_len, private, cred_random) != 0) { ret = CTAP2_ERR_INVALID_COMMAND; goto ga_cleanup; }
        uint16_t salt_blocks = (uint16_t)(params.hs_salt_enc_len / 32);
        for (uint16_t i = 0; i < salt_blocks; i++) {
            if (wc_HmacInit(&hmac, NULL, 0) != 0) { ret = CTAP2_ERR_INVALID_COMMAND; goto ga_cleanup; }
            if (wc_HmacSetKey(&hmac, SHA256, cred_random, HASH_SZ) != 0) { wc_HmacFree(&hmac); ret = CTAP2_ERR_INVALID_COMMAND; goto ga_cleanup; }
            wc_HmacUpdate(&hmac, salt_dec + (i * 32), 32);
            wc_HmacFinal(&hmac, hs_output + (i * 32));
            wc_HmacFree(&hmac);
        }

        if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) { ret = CTAP2_ERR_INVALID_COMMAND; goto ga_cleanup; }
        memset(iv, 0, sizeof(iv));
        if (wc_AesSetKey(&aes, shared + HASH_SZ, 32, iv, AES_ENCRYPTION) != 0) { wc_AesFree(&aes); ret = CTAP2_ERR_INVALID_COMMAND; goto ga_cleanup; }
        if (wc_AesCbcEncrypt(&aes, salt_dec, hs_output, params.hs_salt_enc_len) != 0) { wc_AesFree(&aes); ret = CTAP2_ERR_INVALID_COMMAND; goto ga_cleanup; }
        wc_AesFree(&aes);

        WOLFCOSE_CBOR_CTX ext;
        cbor_enc_init(&ext, ext_buf, sizeof(ext_buf), 0);
        if (wc_CBOR_EncodeMapStart(&ext, 1) != 0) { ret = CTAP2_ERR_INVALID_COMMAND; goto ga_cleanup; }
        if (cbor_put_text(&ext, "hmac-secret") != 0) { ret = CTAP2_ERR_INVALID_COMMAND; goto ga_cleanup; }
        if (wc_CBOR_EncodeBstr(&ext, salt_dec, params.hs_salt_enc_len) != 0) { ret = CTAP2_ERR_INVALID_COMMAND; goto ga_cleanup; }
        ext_len = (uint16_t)ext.idx;
        ForceZero(shared, sizeof(shared));
        ForceZero(mac, sizeof(mac));
        ForceZero(cred_random, sizeof(cred_random));
        ForceZero(hs_output, sizeof(hs_output));
        ForceZero(salt_dec, sizeof(salt_dec));
    }

    if (build_authdata_assert(rpIdHash, flags, device_get_counter(),
                              ext_len ? ext_buf : NULL, ext_len,
                              authData, sizeof(authData), &authDataLen) != 0) {
        ret = -1; goto ga_cleanup;
    }

    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, authData, authDataLen);
    wc_Sha256Update(&sha, params.clientDataHash, params.cdh_len);
    wc_Sha256Final(&sha, digest);
    wc_Sha256Free(&sha);

    siglen = (word32)wc_ecc_sig_size(&user_ecc);
    ret = wc_ecc_sign_hash(digest, HASH_SZ, sigbuf, &siglen, &rng, &user_ecc);
    if (ret != 0)
        goto ga_cleanup;

    device_counter_inc();

    WOLFCOSE_CBOR_CTX c;
    cbor_enc_init(&c, reply, reply_max, 1);
    reply[0] = CTAP2_ERR_SUCCESS;
    if (wc_CBOR_EncodeMapStart(&c, 4) != 0) { ret = -1; goto ga_cleanup; }
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
    if (wc_CBOR_EncodeUint(&c, 5) != 0) { ret = -1; goto ga_cleanup; }
    if (wc_CBOR_EncodeUint(&c, 1) != 0) { ret = -1; goto ga_cleanup; }

    *reply_len = (uint16_t)c.idx;

ga_cleanup:
    wc_FreeRng(&rng);
    wc_ecc_free(&user_ecc);
    ForceZero(private, sizeof(private));
    if (ret != 0) {
        reply[0] = (ret > 0) ? (uint8_t)ret : CTAP2_ERR_NO_CREDENTIALS;
        *reply_len = 1;
    }
    return 0;
}

static int ctap2_client_pin(const uint8_t *payload, uint16_t payload_len,
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
    uint8_t shared[HASH_SZ * 2]; /* HKDF output: 32-byte HMAC key + 32-byte AES key */
    uint8_t tmp[64];
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
            if (pin_shared_secret(platform_qx, platform_qy, shared) != 0) {
                reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0;
            }
            /* pinAuth = LEFT(HMAC(sharedSecret[0:32], newPinEnc), 16) */
            if (wc_HmacInit(&hmac, NULL, 0) != 0) { return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len); }
            if (wc_HmacSetKey(&hmac, SHA256, shared, HASH_SZ) != 0) { wc_HmacFree(&hmac); return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len); }
            wc_HmacUpdate(&hmac, newPinEnc, newPinEnc_len);
            wc_HmacFinal(&hmac, tmp);
            wc_HmacFree(&hmac);
            if (memcmp(tmp, pin_auth, 16) != 0) {
                reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0;
            }
            /* newPinEnc: AES-256-CBC(sharedSecret[32:], iv=0, padded PIN, 64 bytes) */
            {
                Aes aes;
                uint8_t iv[16] = {0};
                if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) { reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0; }
                if (wc_AesSetKey(&aes, shared + 32, 32, iv, AES_DECRYPTION) != 0) { wc_AesFree(&aes); reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0; }
                if (wc_AesCbcDecrypt(&aes, tmp, newPinEnc, newPinEnc_len) != 0) { wc_AesFree(&aes); reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0; }
                wc_AesFree(&aes);
            }
            /* derive hash */
            uint16_t pin_len = 0;
            for (int i = 0; i < 64; i++) {
                if (tmp[i] == 0) { pin_len = (uint16_t)i; break; }
            }
            if (pin_len == 0) pin_len = 64;
            if (pin_hash_plain(tmp, pin_len, pin_store.pin_hash) != 0) {
                reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0;
            }
            pin_store.retries = PIN_MAX_RETRIES;
            pin_state_save();
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
            if (pin_check_retries() != 0) {
                reply[0] = CTAP2_ERR_PIN_BLOCKED; *reply_len = 1; return 0;
            }
            if (!key_agree || !pin_agree_valid || parse_cose_pubkey(key_agree, key_agree_len, platform_qx, platform_qy) != 0) {
                reply[0] = CTAP2_ERR_INVALID_CBOR; *reply_len = 1; return 0;
            }
            if (!pin_auth || pin_auth_len != 16 || !newPinEnc || newPinEnc_len != 64 || !pinHashEnc || pinHashEnc_len != 16) {
                reply[0] = CTAP2_ERR_INVALID_LENGTH; *reply_len = 1; return 0;
            }
            if (pin_shared_secret(platform_qx, platform_qy, shared) != 0) {
                return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len);
            }
            /* pinHashEnc: AES-256-CBC(sharedSecret[32:], iv=0, LEFT(SHA256(PIN),16)) */
            {
                Aes aes;
                uint8_t iv[16] = {0};
                if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) { return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len); }
                if (wc_AesSetKey(&aes, shared + 32, 32, iv, AES_DECRYPTION) != 0) { wc_AesFree(&aes); return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len); }
                if (wc_AesCbcDecrypt(&aes, tmp, pinHashEnc, pinHashEnc_len) != 0) { wc_AesFree(&aes); return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len); }
                wc_AesFree(&aes);
            }
            if (memcmp(tmp, pin_store.pin_hash, 16) != 0) {
                pin_fail_retry();
                reply[0] = CTAP2_ERR_PIN_INVALID; *reply_len = 1; return 0;
            }
            if (wc_HmacInit(&hmac, NULL, 0) != 0) { return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len); }
            if (wc_HmacSetKey(&hmac, SHA256, shared, HASH_SZ) != 0) { wc_HmacFree(&hmac); return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len); }
            wc_HmacUpdate(&hmac, newPinEnc, newPinEnc_len);
            /* For changePIN, the auth covers both the new PIN and the old hash */
            wc_HmacUpdate(&hmac, pinHashEnc, pinHashEnc_len);
            wc_HmacFinal(&hmac, tmp);
            wc_HmacFree(&hmac);
            if (memcmp(tmp, pin_auth, 16) != 0) {
                pin_fail_retry();
                return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len);
            }
            /* Decrypt newPinEnc (IV=0) */
            {
                Aes aes;
                uint8_t iv[16] = {0};
                if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) { return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len); }
                if (wc_AesSetKey(&aes, shared + 32, 32, iv, AES_DECRYPTION) != 0) { wc_AesFree(&aes); return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len); }
                if (wc_AesCbcDecrypt(&aes, tmp, newPinEnc, newPinEnc_len) != 0) { wc_AesFree(&aes); return write_error(CTAP2_ERR_PIN_AUTH_INVALID, reply, reply_len); }
                wc_AesFree(&aes);
            }
            uint16_t pin_len = 0;
            for (int i = 0; i < 64; i++) {
                if (tmp[i] == 0) { pin_len = (uint16_t)i; break; }
            }
            if (pin_len == 0) pin_len = 64;
            if (pin_hash_plain(tmp, pin_len, pin_store.pin_hash) != 0) {
                reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0;
            }
            pin_store.retries = PIN_MAX_RETRIES;
            pin_state_save();
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
            if (pin_check_retries() != 0) {
                reply[0] = CTAP2_ERR_PIN_BLOCKED; *reply_len = 1; return 0;
            }
            if (!key_agree || !pin_agree_valid || parse_cose_pubkey(key_agree, key_agree_len, platform_qx, platform_qy) != 0) {
                reply[0] = CTAP2_ERR_INVALID_CBOR; *reply_len = 1; return 0;
            }
            if (!pinHashEnc || pinHashEnc_len != 16) {
                reply[0] = CTAP2_ERR_INVALID_LENGTH; *reply_len = 1; return 0;
            }
            if (pin_shared_secret(platform_qx, platform_qy, shared) != 0) {
                reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0;
            }
            /* pinHashEnc for protocol 1 is a single AES block with IV=0. */
            {
                Aes aes;
                uint8_t iv[16] = {0};
                if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) { reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0; }
                if (wc_AesSetKey(&aes, shared + 32, 32, iv, AES_DECRYPTION) != 0) { wc_AesFree(&aes); reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0; }
                if (wc_AesCbcDecrypt(&aes, tmp, pinHashEnc, pinHashEnc_len) != 0) { wc_AesFree(&aes); reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0; }
                wc_AesFree(&aes);
            }
            if (memcmp(tmp, pin_store.pin_hash, 16) != 0) {
                pin_fail_retry();
                reply[0] = CTAP2_ERR_PIN_INVALID; *reply_len = 1; return 0;
            }
            wc_InitRng(&rng);
            pin_reset_token(&rng);
            pin_store.retries = PIN_MAX_RETRIES;
            pin_state_save();
            /* Encrypt pinToken with AES-256-CBC, IV=0, no IV prefix (protocol 1). */
            {
                Aes aes;
                uint8_t iv[16] = {0};
                uint16_t enc_len = sizeof(pin_token);
                if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) { wc_FreeRng(&rng); reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0; }
                if (wc_AesSetKey(&aes, shared + 32, 32, iv, AES_ENCRYPTION) != 0) { wc_AesFree(&aes); wc_FreeRng(&rng); reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0; }
                if (wc_AesCbcEncrypt(&aes, tmp, pin_token, sizeof(pin_token)) != 0) { wc_AesFree(&aes); wc_FreeRng(&rng); reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0; }
                wc_AesFree(&aes);
                WOLFCOSE_CBOR_CTX rc;
                cbor_enc_init(&rc, reply, reply_max, 1);
                reply[0] = CTAP2_ERR_SUCCESS;
                if (wc_CBOR_EncodeMapStart(&rc, 1) != 0) { wc_FreeRng(&rng); return -1; }
                if (wc_CBOR_EncodeUint(&rc, 2) != 0) { wc_FreeRng(&rng); return -1; }
                if (wc_CBOR_EncodeBstr(&rc, tmp, enc_len) != 0) { wc_FreeRng(&rng); return -1; }
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

void ctap2_reset_state(void)
{
    pin_state_reset();
    rk_reset();
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
            rk_reset();
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
