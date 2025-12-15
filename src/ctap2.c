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

struct cbor_buf {
    uint8_t *buf;
    uint16_t cap;
    uint16_t len;
};

static int cbor_put_type_val(struct cbor_buf *b, uint8_t major, uint32_t val)
{
    if (val < 24) {
        if (b->len + 1 > b->cap) return -1;
        b->buf[b->len++] = (uint8_t)((major << 5) | (uint8_t)val);
        return 0;
    } else if (val <= 0xFF) {
        if (b->len + 2 > b->cap) return -1;
        b->buf[b->len++] = (uint8_t)((major << 5) | 24);
        b->buf[b->len++] = (uint8_t)val;
        return 0;
    } else if (val <= 0xFFFF) {
        if (b->len + 3 > b->cap) return -1;
        b->buf[b->len++] = (uint8_t)((major << 5) | 25);
        b->buf[b->len++] = (uint8_t)(val >> 8);
        b->buf[b->len++] = (uint8_t)(val & 0xFF);
        return 0;
    }
    return -1;
}

static int cbor_put_uint(struct cbor_buf *b, uint32_t val)
{
    return cbor_put_type_val(b, 0, val);
}

static int cbor_put_neg(struct cbor_buf *b, int32_t neg_val)
{
    /* neg_val is negative; CBOR stores -1 - value */
    uint32_t val = (uint32_t)(-1 - neg_val);
    return cbor_put_type_val(b, 1, val);
}

static int cbor_put_int(struct cbor_buf *b, int32_t val)
{
    if (val < 0) {
        return cbor_put_neg(b, val);
    }
    return cbor_put_uint(b, (uint32_t)val);
}

static int cbor_put_bytes(struct cbor_buf *b, const uint8_t *data, uint16_t len)
{
    if (cbor_put_type_val(b, 2, len) != 0)
        return -1;
    if (b->len + len > b->cap)
        return -1;
    memcpy(&b->buf[b->len], data, len);
    b->len += len;
    return 0;
}

static int cbor_put_text(struct cbor_buf *b, const char *s)
{
    size_t len = strlen(s);
    if (len > UINT16_MAX)
        return -1;
    if (cbor_put_type_val(b, 3, (uint32_t)len) != 0)
        return -1;
    if (b->len + len > b->cap)
        return -1;
    memcpy(&b->buf[b->len], s, len);
    b->len += (uint16_t)len;
    return 0;
}

static int cbor_put_bool(struct cbor_buf *b, bool v)
{
    return cbor_put_type_val(b, 7, v ? 21 : 20);
}

static int cbor_start_array(struct cbor_buf *b, uint8_t count)
{
    return cbor_put_type_val(b, 4, count);
}

static int cbor_start_map(struct cbor_buf *b, uint8_t count)
{
    return cbor_put_type_val(b, 5, count);
}

/* --- CBOR decoding helpers (minimal, definite lengths only) --- */
static int cbor_read_hdr(const uint8_t *buf, uint16_t len, uint8_t *major, uint32_t *val, uint16_t *consumed)
{
    if (len == 0)
        return -1;
    uint8_t ib = buf[0];
    uint8_t addl = ib & 0x1f;
    *major = ib >> 5;
    *consumed = 1;
    if (addl < 24) {
        *val = addl;
    } else if (addl == 24) {
        if (len < 2) return -1;
        *val = buf[1];
        *consumed = 2;
    } else if (addl == 25) {
        if (len < 3) return -1;
        *val = ((uint32_t)buf[1] << 8) | buf[2];
        *consumed = 3;
    } else if (addl == 26) {
        if (len < 5) return -1;
        *val = ((uint32_t)buf[1] << 24) | ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 8) | buf[4];
        *consumed = 5;
    } else {
        return -1; /* Indefinite/too large not supported */
    }
    return 0;
}

static int cbor_skip(const uint8_t *buf, uint16_t len, uint16_t *consumed)
{
    uint8_t major;
    uint32_t val;
    uint16_t hdr_len;
    if (cbor_read_hdr(buf, len, &major, &val, &hdr_len) != 0)
        return -1;
    if (len < hdr_len)
        return -1;

    const uint8_t *p = buf + hdr_len;
    uint16_t remain = (uint16_t)(len - hdr_len);
    switch (major) {
        case 0: /* uint */
        case 1: /* nint */
        case 7: /* simple */
            *consumed = hdr_len;
            return 0;
        case 2: /* bytes */
        case 3: /* text */
            if (remain < val)
                return -1;
            *consumed = (uint16_t)(hdr_len + val);
            return 0;
        case 4: { /* array */
            uint16_t total = hdr_len;
            for (uint32_t i = 0; i < val; i++) {
                uint16_t inner = 0;
                if (cbor_skip(p, remain, &inner) != 0)
                    return -1;
                total += inner;
                if (remain < inner)
                    return -1;
                p += inner;
                remain = (uint16_t)(remain - inner);
            }
            *consumed = total;
            return 0;
        }
        case 5: { /* map */
            uint16_t total = hdr_len;
            for (uint32_t i = 0; i < val; i++) {
                uint16_t inner = 0;
                if (cbor_skip(p, remain, &inner) != 0)
                    return -1;
                total += inner;
                if (remain < inner)
                    return -1;
                p += inner;
                remain = (uint16_t)(remain - inner);
                if (cbor_skip(p, remain, &inner) != 0)
                    return -1;
                total += inner;
                if (remain < inner)
                    return -1;
                p += inner;
                remain = (uint16_t)(remain - inner);
            }
            *consumed = total;
            return 0;
        }
        default:
            return -1;
    }
}

static int cbor_read_bytes(const uint8_t *buf, uint16_t len, const uint8_t **out, uint32_t *out_len, uint16_t *consumed)
{
    uint8_t major;
    uint32_t val;
    uint16_t hdr_len;
    if (cbor_read_hdr(buf, len, &major, &val, &hdr_len) != 0)
        return -1;
    if (major != 2)
        return -1;
    if (len < hdr_len + val)
        return -1;
    *out = buf + hdr_len;
    *out_len = val;
    *consumed = (uint16_t)(hdr_len + val);
    return 0;
}

static int cbor_read_text(const uint8_t *buf, uint16_t len, const uint8_t **out, uint32_t *out_len, uint16_t *consumed)
{
    uint8_t major;
    uint32_t val;
    uint16_t hdr_len;
    if (cbor_read_hdr(buf, len, &major, &val, &hdr_len) != 0)
        return -1;
    if (major != 3)
        return -1;
    if (len < hdr_len + val)
        return -1;
    *out = buf + hdr_len;
    *out_len = val;
    *consumed = (uint16_t)(hdr_len + val);
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

static int hkdf32(const uint8_t *ikm, uint16_t ikm_len,
                  const uint8_t *info, uint16_t info_len,
                  uint8_t *out)
{
    uint8_t prk_val[HASH_SZ];
    uint8_t t[HASH_SZ];
    uint8_t salt[HASH_SZ] = {0};
    Hmac prk, okm;
    int r = wc_HmacInit(&prk, NULL, 0);
    if (r != 0) return -1;
    r = wc_HmacSetKey(&prk, SHA256, salt, sizeof(salt));
    if (r != 0) { wc_HmacFree(&prk); return -1; }
    wc_HmacUpdate(&prk, ikm, ikm_len);
    wc_HmacFinal(&prk, prk_val);
    wc_HmacFree(&prk);

    r = wc_HmacInit(&okm, NULL, 0);
    if (r != 0) { ForceZero(prk_val, sizeof(prk_val)); return -1; }
    r = wc_HmacSetKey(&okm, SHA256, prk_val, sizeof(prk_val));
    if (r != 0) { wc_HmacFree(&okm); ForceZero(prk_val, sizeof(prk_val)); return -1; }
    wc_HmacUpdate(&okm, info, info_len);
    uint8_t one = 0x01;
    wc_HmacUpdate(&okm, &one, 1);
    wc_HmacFinal(&okm, t);
    wc_HmacFree(&okm);
    memcpy(out, t, HASH_SZ);
    ForceZero(prk_val, sizeof(prk_val));
    ForceZero(t, sizeof(t));
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

static int encode_cose_pubkey(struct cbor_buf *c, const uint8_t *qx, const uint8_t *qy)
{
    if (cbor_start_map(c, 5) != 0) return -1;
    if (cbor_put_int(c, COSE_KEY_KTY_LABEL) != 0) return -1;
    if (cbor_put_uint(c, COSE_KTY_EC2) != 0) return -1;
    if (cbor_put_int(c, COSE_KEY_ALG_LABEL) != 0) return -1;
    if (cbor_put_int(c, COSE_ALG_ES256) != 0) return -1;
    if (cbor_put_int(c, COSE_KEY_CRV_LABEL) != 0) return -1;
    if (cbor_put_uint(c, COSE_CRV_P256) != 0) return -1;
    if (cbor_put_int(c, COSE_KEY_X_LABEL) != 0) return -1;
    if (cbor_put_bytes(c, qx, ECC_SZ) != 0) return -1;
    if (cbor_put_int(c, COSE_KEY_Y_LABEL) != 0) return -1;
    if (cbor_put_bytes(c, qy, ECC_SZ) != 0) return -1;
    return 0;
}

static int build_authdata_attested(const uint8_t *rpIdHash, uint8_t flags, uint32_t counter,
                                   const uint8_t *credId, uint16_t credIdLen,
                                   const uint8_t *pubkey_qx, const uint8_t *pubkey_qy,
                                   uint8_t *authData, uint16_t authDataCap, uint16_t *authDataLen)
{
    uint8_t aaguid[16] = {0};
    uint16_t idx = 0;
    uint8_t counter_be[4];
    struct cbor_buf cose = {0};

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

    cose.buf = &authData[idx];
    cose.cap = (uint16_t)(authDataCap - idx);
    cose.len = 0;
    if (encode_cose_pubkey(&cose, pubkey_qx, pubkey_qy) != 0)
        return -1;
    idx += cose.len;
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

static int parse_cose_pubkey(const uint8_t *buf, uint16_t len, uint8_t *qx, uint8_t *qy)
{
    uint8_t major; uint32_t items; uint16_t cons;
    const uint8_t *p = buf; uint16_t remain = len;
    bool kty_ok = false, crv_ok = false, alg_ok = false, x_ok = false, y_ok = false;
    if (cbor_read_hdr(p, remain, &major, &items, &cons) != 0 || major != 5)
        return -1;
    p += cons; remain -= cons;
    for (uint32_t i = 0; i < items; i++) {
        int32_t key = 0;
        uint16_t kcons;
        if (cbor_read_hdr(p, remain, &major, (uint32_t *)&key, &kcons) != 0)
            return -1;
        if (major == 1) { /* negative */
            key = -1 - (int32_t)key;
        }
        p += kcons; remain -= kcons;
        switch (key) {
            case COSE_KEY_KTY_LABEL: {
                uint8_t vmajor; uint32_t vval; uint16_t vcons;
                if (cbor_read_hdr(p, remain, &vmajor, &vval, &vcons) != 0)
                    return -1;
                if (vmajor == 0 && vval == COSE_KTY_EC2)
                    kty_ok = true;
                p += vcons; remain -= vcons;
                break;
            }
            case COSE_KEY_ALG_LABEL: {
                uint8_t vmajor; uint32_t vval; uint16_t vcons;
                if (cbor_read_hdr(p, remain, &vmajor, &vval, &vcons) != 0)
                    return -1;
                if (vmajor == 1) {
                    int32_t a = -1 - (int32_t)vval;
                    if (a == COSE_ALG_ECDH_ES_HKDF256 || a == COSE_ALG_ES256)
                        alg_ok = true;
                }
                p += vcons; remain -= vcons;
                break;
            }
            case COSE_KEY_CRV_LABEL: {
                uint8_t vmajor; uint32_t vval; uint16_t vcons;
                if (cbor_read_hdr(p, remain, &vmajor, &vval, &vcons) != 0)
                    return -1;
                if (vmajor == 0 && vval == COSE_CRV_P256)
                    crv_ok = true;
                p += vcons; remain -= vcons;
                break;
            }
            case COSE_KEY_X_LABEL: {
                const uint8_t *vx; uint32_t vlen; uint16_t vcons;
                if (cbor_read_bytes(p, remain, &vx, &vlen, &vcons) != 0)
                    return -1;
                if (vlen == ECC_SZ) {
                    memcpy(qx, vx, ECC_SZ);
                    x_ok = true;
                }
                p += vcons; remain -= vcons;
                break;
            }
            case COSE_KEY_Y_LABEL: {
                const uint8_t *vy; uint32_t vlen; uint16_t vcons;
                if (cbor_read_bytes(p, remain, &vy, &vlen, &vcons) != 0)
                    return -1;
                if (vlen == ECC_SZ) {
                    memcpy(qy, vy, ECC_SZ);
                    y_ok = true;
                }
                p += vcons; remain -= vcons;
                break;
            }
            default: {
                uint16_t skip;
                if (cbor_skip(p, remain, &skip) != 0)
                    return -1;
                p += skip; remain -= skip;
                break;
            }
        }
    }
    return (kty_ok && crv_ok && alg_ok && x_ok && y_ok) ? 0 : -1;
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

static int parse_makecred(const uint8_t *buf, uint16_t len, struct mc_params *out)
{
    uint8_t major;
    uint32_t items;
    uint16_t cons;
    const uint8_t *p = buf;
    uint16_t remain = len;

    memset(out, 0, sizeof(*out));
    if (cbor_read_hdr(p, remain, &major, &items, &cons) != 0 || major != 5)
        return -1;
    p += cons; remain -= cons;

    for (uint32_t i = 0; i < items; i++) {
        uint32_t key;
        uint16_t kcons;
        if (cbor_read_hdr(p, remain, &major, &key, &kcons) != 0 || major != 0)
            return -1;
        p += kcons; remain -= kcons;

        switch (key) {
            case 1: { /* clientDataHash */
                const uint8_t *cdh; uint32_t cdh_len; uint16_t vcons;
                if (cbor_read_bytes(p, remain, &cdh, &cdh_len, &vcons) != 0)
                    return -1;
                out->clientDataHash = cdh;
                out->cdh_len = cdh_len;
                p += vcons; remain -= vcons;
                break;
            }
            case 2: { /* rp */
                uint8_t mmajor; uint32_t mitems; uint16_t vcons;
                if (cbor_read_hdr(p, remain, &mmajor, &mitems, &vcons) != 0 || mmajor != 5)
                    return -1;
                p += vcons; remain -= vcons;
                for (uint32_t j = 0; j < mitems; j++) {
                    const uint8_t *t; uint32_t tlen; uint16_t tcons;
                    if (cbor_read_text(p, remain, &t, &tlen, &tcons) != 0)
                        return -1;
                    p += tcons; remain -= tcons;
                    /* value */
                    if (tlen == 2 && t[0] == 'i' && t[1] == 'd') {
                        const uint8_t *rpv; uint32_t rplen; uint16_t rvcons;
                        if (cbor_read_text(p, remain, &rpv, &rplen, &rvcons) != 0)
                            return -1;
                        out->rp_id = rpv;
                        out->rp_id_len = rplen;
                        p += rvcons; remain -= rvcons;
                    } else {
                        uint16_t skip;
                        if (cbor_skip(p, remain, &skip) != 0)
                            return -1;
                        p += skip; remain -= skip;
                    }
                }
                break;
            }
            case 4: { /* pubKeyCredParams */
                uint8_t amajor; uint32_t acount; uint16_t vcons;
                if (cbor_read_hdr(p, remain, &amajor, &acount, &vcons) != 0 || amajor != 4)
                    return -1;
                p += vcons; remain -= vcons;
                for (uint32_t j = 0; j < acount; j++) {
                    uint8_t mmajor; uint32_t mitems; uint16_t mcons;
                    if (cbor_read_hdr(p, remain, &mmajor, &mitems, &mcons) != 0 || mmajor != 5)
                        return -1;
                    p += mcons; remain -= mcons;
                    bool type_ok = false;
                    bool alg_ok = false;
                    for (uint32_t k = 0; k < mitems; k++) {
                        uint32_t mkey; uint16_t kkcons; uint16_t key_used = 0;
                        uint8_t key_major;
                        const uint8_t *tkey = NULL; uint32_t tlen = 0; uint16_t tcons = 0;
                        if (cbor_read_hdr(p, remain, &key_major, &mkey, &kkcons) != 0)
                            return -1;
                        if (key_major == 3) { /* text label (e.g., "type"/"alg") */
                            if (cbor_read_text(p, remain, &tkey, &tlen, &tcons) != 0)
                                return -1;
                            key_used = tcons;
                        } else if (key_major == 0) {
                            key_used = kkcons;
                        } else {
                            return -1;
                        }
                        if (remain < key_used)
                            return -1;
                        p += key_used; remain -= key_used;
                        bool key_is_type = (key_major == 0 && mkey == 1) ||
                                           (key_major == 3 && tlen == 4 && memcmp(tkey, "type", 4) == 0);
                        bool key_is_alg = (key_major == 0 && mkey == 3) ||
                                          (key_major == 3 && tlen == 3 && memcmp(tkey, "alg", 3) == 0);
                        if (key_is_type) { /* type */
                            const uint8_t *tv; uint32_t tlen; uint16_t tvcons;
                            if (cbor_read_text(p, remain, &tv, &tlen, &tvcons) != 0)
                                return -1;
                            if (tlen == 10 && memcmp(tv, "public-key", 10) == 0)
                                type_ok = true;
                            p += tvcons; remain -= tvcons;
                        } else if (key_is_alg) { /* alg */
                            uint8_t alg_major; uint32_t alg_val; uint16_t alg_cons;
                            if (cbor_read_hdr(p, remain, &alg_major, &alg_val, &alg_cons) != 0)
                                return -1;
                            if (alg_major == 1) { /* negative */
                                int32_t aval = -1 - (int32_t)alg_val;
                                if (aval == COSE_ALG_ES256)
                                    alg_ok = true;
                            }
                            p += alg_cons; remain -= alg_cons;
                        } else {
                            uint16_t skip;
                            if (cbor_skip(p, remain, &skip) != 0)
                                return -1;
                            p += skip; remain -= skip;
                        }
                    }
                    if (type_ok && alg_ok)
                        out->es256_ok = true;
                }
                break;
            }
            case 7: { /* options */
                uint8_t mmajor; uint32_t mitems; uint16_t vcons;
                if (cbor_read_hdr(p, remain, &mmajor, &mitems, &vcons) != 0 || mmajor != 5)
                    return -1;
                p += vcons; remain -= vcons;
                for (uint32_t j = 0; j < mitems; j++) {
                    const uint8_t *tn; uint32_t tnlen; uint16_t tncons;
                    if (cbor_read_text(p, remain, &tn, &tnlen, &tncons) != 0)
                        return -1;
                    p += tncons; remain -= tncons;
                    uint8_t vmajor; uint32_t vval; uint16_t vcons2;
                    if (cbor_read_hdr(p, remain, &vmajor, &vval, &vcons2) != 0)
                        return -1;
                    if (tnlen == 2 && tn[0] == 'u' && tn[1] == 'v') {
                        if (vmajor == 7 && vval == 21)
                            out->uv_required = true;
                    } else if (tnlen == 2 && tn[0] == 'r' && tn[1] == 'k') {
                        if (vmajor == 7 && vval == 21)
                            out->rk = true;
                    }
                    p += vcons2; remain -= vcons2;
                }
                break;
            }
            case 8: { /* pinAuth */
                const uint8_t *pa; uint32_t palen; uint16_t vcons;
                if (cbor_read_bytes(p, remain, &pa, &palen, &vcons) != 0)
                    return -1;
                out->pin_auth = pa;
                out->pin_auth_len = palen;
                p += vcons; remain -= vcons;
                break;
            }
            case 9: { /* pinProtocol */
                uint8_t vmajor; uint32_t vval; uint16_t vcons;
                if (cbor_read_hdr(p, remain, &vmajor, &vval, &vcons) != 0)
                    return -1;
                if (vmajor == 0)
                    out->pin_protocol = (int)vval;
                p += vcons; remain -= vcons;
                break;
            }
            default: {
                uint16_t skip;
                if (cbor_skip(p, remain, &skip) != 0)
                    return -1;
                p += skip; remain -= skip;
                break;
            }
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

static bool key_eq(const uint8_t *s, uint32_t len, const char *lit)
{
    size_t l = strlen(lit);
    return len == l && memcmp(s, lit, l) == 0;
}

static int parse_hmac_secret_input(const uint8_t *buf, uint16_t len, struct ga_params *out)
{
    uint8_t major; uint32_t items; uint16_t cons;
    const uint8_t *p = buf; uint16_t remain = len;

    if (cbor_read_hdr(p, remain, &major, &items, &cons) != 0)
        return -1;
    if (major != 5)
        return -1;
    p += cons; remain -= cons;
    for (uint32_t i = 0; i < items; i++) {
        uint8_t kmajor; uint32_t kval; uint16_t kcons;
        const uint8_t *ktext = NULL; uint32_t klen = 0; uint16_t ktext_cons = 0;
        if (cbor_read_hdr(p, remain, &kmajor, &kval, &kcons) != 0)
            return -1;
        if (kmajor == 3) {
            if (cbor_read_text(p, remain, &ktext, &klen, &ktext_cons) != 0)
                return -1;
            if (remain < ktext_cons)
                return -1;
            p += ktext_cons; remain -= ktext_cons;
        } else {
            if (remain < kcons)
                return -1;
            p += kcons; remain -= kcons;
        }

        bool key_is_hs = (kmajor == 3 && key_eq(ktext, klen, "hmac-secret"));
        if (!key_is_hs) {
            uint16_t skip;
            if (cbor_skip(p, remain, &skip) != 0)
                return -1;
            p += skip; remain = (uint16_t)(remain - skip);
            continue;
        }

        /* Parse inner hmac-secret map */
        uint8_t imajor; uint32_t iitems; uint16_t icons;
        if (cbor_read_hdr(p, remain, &imajor, &iitems, &icons) != 0 || imajor != 5)
            return -1;
        p += icons; remain -= icons;
        for (uint32_t j = 0; j < iitems; j++) {
            uint8_t ikmajor; uint32_t ikval; uint16_t ikcons;
            const uint8_t *iktext = NULL; uint32_t iklen = 0; uint16_t iktext_cons = 0;
            if (cbor_read_hdr(p, remain, &ikmajor, &ikval, &ikcons) != 0)
                return -1;
            if (ikmajor == 3) {
                if (cbor_read_text(p, remain, &iktext, &iklen, &iktext_cons) != 0)
                    return -1;
                if (remain < iktext_cons)
                    return -1;
                p += iktext_cons; remain -= iktext_cons;
            } else {
                if (remain < ikcons)
                    return -1;
                p += ikcons; remain -= ikcons;
            }

            bool key_is_agree = (ikmajor == 0 && ikval == 1) || (ikmajor == 3 && key_eq(iktext, iklen, "keyAgreement"));
            bool key_is_salt_enc = (ikmajor == 0 && ikval == 2) || (ikmajor == 3 && key_eq(iktext, iklen, "saltEnc"));
            bool key_is_salt_auth = (ikmajor == 0 && ikval == 3) || (ikmajor == 3 && key_eq(iktext, iklen, "saltAuth"));
            bool key_is_pin_protocol = (ikmajor == 0 && ikval == 4) || (ikmajor == 3 && key_eq(iktext, iklen, "pinProtocol"));

            if (key_is_agree) {
                uint16_t skip;
                if (cbor_skip(p, remain, &skip) != 0)
                    return -1;
                if (skip > remain)
                    return -1;
                if (parse_cose_pubkey(p, skip, out->hs_platform_qx, out->hs_platform_qy) != 0)
                    return -1;
                out->hmac_secret_requested = true;
                out->hs_key_set = true;
                p += skip; remain = (uint16_t)(remain - skip);
            } else if (key_is_salt_enc) {
                const uint8_t *b; uint32_t blen; uint16_t bcons;
                if (cbor_read_bytes(p, remain, &b, &blen, &bcons) != 0)
                    return -1;
                if (blen != 32 && blen != 64)
                    return -1;
                out->hs_salt_enc = b;
                out->hs_salt_enc_len = blen;
                out->hmac_secret_requested = true;
                p += bcons; remain -= bcons;
            } else if (key_is_salt_auth) {
                const uint8_t *b; uint32_t blen; uint16_t bcons;
                if (cbor_read_bytes(p, remain, &b, &blen, &bcons) != 0)
                    return -1;
                if (blen != 16)
                    return -1;
                out->hs_salt_auth = b;
                out->hs_salt_auth_len = blen;
                out->hmac_secret_requested = true;
                p += bcons; remain -= bcons;
            } else if (key_is_pin_protocol) {
                uint8_t vmajor; uint32_t vval; uint16_t vcons;
                if (cbor_read_hdr(p, remain, &vmajor, &vval, &vcons) != 0)
                    return -1;
                if (vmajor != 0)
                    return -1;
                out->hs_pin_protocol = (int)vval;
                out->hmac_secret_requested = true;
                p += vcons; remain -= vcons;
            } else {
                uint16_t skip;
                if (cbor_skip(p, remain, &skip) != 0)
                    return -1;
                p += skip; remain = (uint16_t)(remain - skip);
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
    uint8_t major; uint32_t items; uint16_t cons;
    const uint8_t *p = buf; uint16_t remain = len;
    memset(out, 0, sizeof(*out));

    if (cbor_read_hdr(p, remain, &major, &items, &cons) != 0 || major != 5)
        return -1;
    p += cons; remain -= cons;

    for (uint32_t i = 0; i < items; i++) {
        uint32_t key; uint16_t kcons;
        if (cbor_read_hdr(p, remain, &major, &key, &kcons) != 0 || major != 0)
            return -1;
        p += kcons; remain -= kcons;

        switch (key) {
            case 1: { /* rpId */
                const uint8_t *rp; uint32_t rplen; uint16_t vcons;
                if (cbor_read_text(p, remain, &rp, &rplen, &vcons) != 0)
                    return -1;
                out->rp_id = rp; out->rp_id_len = rplen;
                p += vcons; remain -= vcons;
                break;
            }
            case 2: { /* clientDataHash */
                const uint8_t *cdh; uint32_t cdh_len; uint16_t vcons;
                if (cbor_read_bytes(p, remain, &cdh, &cdh_len, &vcons) != 0)
                    return -1;
                out->clientDataHash = cdh; out->cdh_len = cdh_len;
                p += vcons; remain -= vcons;
                break;
            }
            case 3: { /* allowList */
                uint8_t amajor; uint32_t acount; uint16_t vcons;
                if (cbor_read_hdr(p, remain, &amajor, &acount, &vcons) != 0 || amajor != 4)
                    return -1;
                p += vcons; remain -= vcons;
                if (acount == 0) {
                    out->allow_rk = true;
                    out->allow_list = NULL;
                    out->allow_list_len = 0;
                    out->allow_count = 0;
                    break;
                }
                /* Record raw allowList for later scanning */
                out->allow_list = p;
                out->allow_count = acount;
                /* Compute total length of the array content */
                uint32_t allow_len = 0;
                uint16_t skip_len = 0;
                uint16_t tmp_remain = remain;
                const uint8_t *tmp_p = p;
                for (uint32_t i = 0; i < acount; i++) {
                    if (cbor_skip(tmp_p, tmp_remain, &skip_len) != 0)
                        return -1;
                    allow_len += skip_len;
                    if (tmp_remain < skip_len)
                        return -1;
                    tmp_p += skip_len;
                    tmp_remain = (uint16_t)(tmp_remain - skip_len);
                }
                out->allow_list_len = allow_len;
                /* Advance main cursor past the array */
                if (remain < allow_len)
                    return -1;
                p += allow_len;
                remain = (uint16_t)(remain - allow_len);
                break;
            }
            case 4: { /* extensions */
                uint16_t skip;
                if (cbor_skip(p, remain, &skip) != 0)
                    return -1;
                if (parse_hmac_secret_input(p, skip, out) != 0)
                    return -1;
                p += skip; remain = (uint16_t)(remain - skip);
                break;
            }
            case 5: { /* options */
                uint8_t mmajor; uint32_t mitems; uint16_t vcons;
                if (cbor_read_hdr(p, remain, &mmajor, &mitems, &vcons) != 0 || mmajor != 5)
                    return -1;
                p += vcons; remain -= vcons;
                for (uint32_t j = 0; j < mitems; j++) {
                    const uint8_t *tn; uint32_t tnlen; uint16_t tncons;
                    if (cbor_read_text(p, remain, &tn, &tnlen, &tncons) != 0)
                        return -1;
                    p += tncons; remain -= tncons;
                    uint8_t vmajor; uint32_t vval; uint16_t vcons2;
                    if (cbor_read_hdr(p, remain, &vmajor, &vval, &vcons2) != 0)
                        return -1;
                    if (tnlen == 2 && tn[0] == 'u' && tn[1] == 'v') {
                        if (vmajor == 7 && vval == 21)
                            out->uv_required = true;
                    }
                    p += vcons2; remain -= vcons2;
                }
                break;
            }
            case 6: { /* pinAuth */
                const uint8_t *pa; uint32_t palen; uint16_t vcons;
                if (cbor_read_bytes(p, remain, &pa, &palen, &vcons) != 0)
                    return -1;
                out->pin_auth = pa; out->pin_auth_len = palen;
                p += vcons; remain -= vcons;
                break;
            }
            case 7: { /* pinProtocol */
                uint8_t vmajor; uint32_t vval; uint16_t vcons;
                if (cbor_read_hdr(p, remain, &vmajor, &vval, &vcons) != 0)
                    return -1;
                if (vmajor == 0)
                    out->pin_protocol = (int)vval;
                p += vcons; remain -= vcons;
                break;
            }
            default: {
                uint16_t skip;
                if (cbor_skip(p, remain, &skip) != 0)
                    return -1;
                p += skip; remain -= skip;
                break;
            }
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
    struct cbor_buf c = {
        .buf = reply,
        .cap = reply_max,
        .len = 0
    };

    if (reply_max < 1)
        return -1;

    /* Reserve status byte at [0]; CBOR starts at [1]. */
    c.len = 1;
    reply[0] = CTAP2_ERR_SUCCESS;

    /* Map entries: versions, extensions, aaguid, options, maxMsgSize, pinProtocols,
     * maxCredentialCountInList, maxCredentialIdLength
     */
    const uint8_t map_items = 8;
    if (cbor_start_map(&c, map_items) != 0) return -1;

    /* 1: versions */
    if (cbor_put_uint(&c, 1) != 0) return -1;
    if (cbor_start_array(&c, 1) != 0) return -1;
    if (cbor_put_text(&c, "FIDO_2_0") != 0) return -1;
    //if (cbor_put_text(&c, "U2F_V2") != 0) return -1;

    /* 2: extensions */
    if (cbor_put_uint(&c, 2) != 0) return -1;
    if (cbor_start_array(&c, 1) != 0) return -1;
    if (cbor_put_text(&c, "hmac-secret") != 0) return -1;

    /* 3: aaguid */
    if (cbor_put_uint(&c, 3) != 0) return -1;
    if (cbor_put_bytes(&c, fidelio_aaguid, sizeof(fidelio_aaguid)) != 0) return -1;

    /* 4: options map */
    if (cbor_put_uint(&c, 4) != 0) return -1;
    if (cbor_start_map(&c, 4) != 0) return -1;
    if (cbor_put_text(&c, "rk") != 0) return -1;
    if (cbor_put_bool(&c, false) != 0) return -1;
    if (cbor_put_text(&c, "up") != 0) return -1;
    if (cbor_put_bool(&c, true) != 0) return -1;
    if (cbor_put_text(&c, "uv") != 0) return -1;
    if (cbor_put_bool(&c, false) != 0) return -1;
    if (cbor_put_text(&c, "clientPin") != 0) return -1;
    if (cbor_put_bool(&c, true) != 0) return -1;

    /* 5: maxMsgSize */
    if (cbor_put_uint(&c, 5) != 0) return -1;
    if (cbor_put_uint(&c, 1024) != 0) return -1;

    /* 6: pinProtocols */
    if (cbor_put_uint(&c, 6) != 0) return -1;
    if (cbor_start_array(&c, 1) != 0) return -1;
    if (cbor_put_uint(&c, CTAP2_PIN_PROTOCOL_SUPPORTED) != 0) return -1;

    /* 7: maxCredentialCountInList */
    if (cbor_put_uint(&c, 7) != 0) return -1;
    if (cbor_put_uint(&c, 8) != 0) return -1;

    /* 8: maxCredentialIdLength */
    if (cbor_put_uint(&c, 8) != 0) return -1;
    if (cbor_put_uint(&c, 128) != 0) return -1;

    /* (algorithms omitted for now; add back when stable) */

    *reply_len = c.len;
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

    if (build_authdata_attested(rpIdHash, flags, device_get_counter(), credId, credIdLen, qx, qy,
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
    struct cbor_buf c = {.buf = reply, .cap = reply_max, .len = 1};
    reply[0] = CTAP2_ERR_SUCCESS;
    if (cbor_start_map(&c, 3) != 0) { ret = -1; goto cleanup; }
    if (cbor_put_uint(&c, 1) != 0) { ret = -1; goto cleanup; }
    if (cbor_put_text(&c, "packed") != 0) { ret = -1; goto cleanup; }
    if (cbor_put_uint(&c, 2) != 0) { ret = -1; goto cleanup; }
    if (cbor_put_bytes(&c, authData, authDataLen) != 0) { ret = -1; goto cleanup; }
    if (cbor_put_uint(&c, 3) != 0) { ret = -1; goto cleanup; }
    if (cbor_start_map(&c, 3) != 0) { ret = -1; goto cleanup; }
    if (cbor_put_text(&c, "alg") != 0) { ret = -1; goto cleanup; }
    if (cbor_put_int(&c, COSE_ALG_ES256) != 0) { ret = -1; goto cleanup; }
    if (cbor_put_text(&c, "sig") != 0) { ret = -1; goto cleanup; }
    if (cbor_put_bytes(&c, signature, (uint16_t)siglen) != 0) { ret = -1; goto cleanup; }
    if (cbor_put_text(&c, "x5c") != 0) { ret = -1; goto cleanup; }
    if (cbor_start_array(&c, 1) != 0) { ret = -1; goto cleanup; }
    if (cbor_put_bytes(&c, cert_att_der, cert_att_der_len) != 0) { ret = -1; goto cleanup; }

    *reply_len = c.len;
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
            uint8_t major; uint32_t mitems; uint16_t cons;
            const uint8_t *p = params.allow_list + allow_off;
            uint16_t remain = (uint16_t)(params.allow_list_len - allow_off);
            if (cbor_read_hdr(p, remain, &major, &mitems, &cons) != 0 || major != 5)
                break;
            p += cons; remain -= cons;
            const uint8_t *desc_id = NULL; uint32_t desc_id_len = 0;
            for (uint32_t j = 0; j < mitems; j++) {
                uint32_t mkey; uint16_t mkcons; uint16_t key_used = 0;
                uint8_t key_major;
                const uint8_t *tkey = NULL; uint32_t tlen = 0; uint16_t tcons = 0;
                if (cbor_read_hdr(p, remain, &key_major, &mkey, &mkcons) != 0)
                    break;
                if (key_major == 3) {
                    if (cbor_read_text(p, remain, &tkey, &tlen, &tcons) != 0)
                        break;
                    key_used = tcons;
                } else if (key_major == 0) {
                    key_used = mkcons;
                } else {
                    break;
                }
                if (remain < key_used)
                    break;
                p += key_used; remain -= key_used;
                bool key_is_type = (key_major == 0 && mkey == 1) ||
                                   (key_major == 3 && tlen == 4 && memcmp(tkey, "type", 4) == 0);
                bool key_is_id = (key_major == 0 && mkey == 2) ||
                                 (key_major == 3 && tlen == 2 && memcmp(tkey, "id", 2) == 0);
                if (key_is_type) {
                    const uint8_t *tv; uint32_t tlenv; uint16_t tvcons;
                    if (cbor_read_text(p, remain, &tv, &tlenv, &tvcons) != 0)
                        break;
                    p += tvcons; remain -= tvcons;
                } else if (key_is_id) {
                    const uint8_t *idv; uint32_t idlen; uint16_t idcons;
                    if (cbor_read_bytes(p, remain, &idv, &idlen, &idcons) != 0)
                        break;
                    desc_id = idv; desc_id_len = idlen;
                    p += idcons; remain -= idcons;
                } else {
                    uint16_t skip;
                    if (cbor_skip(p, remain, &skip) != 0)
                        break;
                    p += skip; remain -= skip;
                }
            }
            allow_off += (params.allow_list_len - remain - allow_off > 0) ? (uint32_t)((params.allow_list_len - remain) - allow_off) : 0;
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

        struct cbor_buf ext = {.buf = ext_buf, .cap = sizeof(ext_buf), .len = 0};
        if (cbor_start_map(&ext, 1) != 0) { ret = CTAP2_ERR_INVALID_COMMAND; goto ga_cleanup; }
        if (cbor_put_text(&ext, "hmac-secret") != 0) { ret = CTAP2_ERR_INVALID_COMMAND; goto ga_cleanup; }
        if (cbor_put_bytes(&ext, salt_dec, (uint16_t)params.hs_salt_enc_len) != 0) { ret = CTAP2_ERR_INVALID_COMMAND; goto ga_cleanup; }
        ext_len = ext.len;
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

    struct cbor_buf c = {.buf = reply, .cap = reply_max, .len = 1};
    reply[0] = CTAP2_ERR_SUCCESS;
    if (cbor_start_map(&c, 4) != 0) { ret = -1; goto ga_cleanup; }
    if (cbor_put_uint(&c, 1) != 0) { ret = -1; goto ga_cleanup; }
    if (cbor_start_map(&c, 2) != 0) { ret = -1; goto ga_cleanup; }
    if (cbor_put_text(&c, "id") != 0) { ret = -1; goto ga_cleanup; }
    if (cbor_put_bytes(&c, params.cred_id, (uint16_t)params.cred_id_len) != 0) { ret = -1; goto ga_cleanup; }
    if (cbor_put_text(&c, "type") != 0) { ret = -1; goto ga_cleanup; }
    if (cbor_put_text(&c, "public-key") != 0) { ret = -1; goto ga_cleanup; }

    if (cbor_put_uint(&c, 2) != 0) { ret = -1; goto ga_cleanup; }
    if (cbor_put_bytes(&c, authData, authDataLen) != 0) { ret = -1; goto ga_cleanup; }
    if (cbor_put_uint(&c, 3) != 0) { ret = -1; goto ga_cleanup; }
    if (cbor_put_bytes(&c, sigbuf, (uint16_t)siglen) != 0) { ret = -1; goto ga_cleanup; }
    if (cbor_put_uint(&c, 5) != 0) { ret = -1; goto ga_cleanup; }
    if (cbor_put_uint(&c, 1) != 0) { ret = -1; goto ga_cleanup; }

    *reply_len = c.len;

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
    uint8_t major; uint32_t items; uint16_t cons;
    const uint8_t *p = payload + 1;
    uint16_t remain = payload_len - 1;
    uint32_t pinProtocol = 0, subCmd = 0;
    const uint8_t *key_agree = NULL; uint32_t key_agree_len = 0;
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

    if (cbor_read_hdr(p, remain, &major, &items, &cons) != 0 || major != 5)
        return -1;
    p += cons; remain -= cons;
    for (uint32_t i = 0; i < items; i++) {
        uint32_t key; uint16_t kcons;
        if (cbor_read_hdr(p, remain, &major, &key, &kcons) != 0 || major != 0)
            return -1;
        p += kcons; remain -= kcons;
        switch (key) {
            case 1: { /* pinProtocol */
                uint8_t vmajor; uint32_t vval; uint16_t vcons;
                if (cbor_read_hdr(p, remain, &vmajor, &vval, &vcons) != 0)
                    return -1;
                pinProtocol = vval;
                p += vcons; remain -= vcons;
                break;
            }
            case 2: { /* subCmd */
                uint8_t vmajor; uint32_t vval; uint16_t vcons;
                if (cbor_read_hdr(p, remain, &vmajor, &vval, &vcons) != 0)
                    return -1;
                subCmd = vval;
                p += vcons; remain -= vcons;
                break;
            }
            case 3: { /* keyAgreement */
                uint16_t skip;
                if (cbor_skip(p, remain, &skip) != 0)
                    return -1;
                key_agree = p;
                key_agree_len = skip;
                p += skip; remain -= skip;
                break;
            }
            case 4: { /* pinAuth */
                const uint8_t *pa; uint32_t palen; uint16_t vcons;
                if (cbor_read_bytes(p, remain, &pa, &palen, &vcons) != 0)
                    return -1;
                pin_auth = pa; pin_auth_len = palen;
                p += vcons; remain -= vcons;
                break;
            }
            case 5: { /* newPinEnc */
                const uint8_t *nv; uint32_t nlen; uint16_t vcons;
                if (cbor_read_bytes(p, remain, &nv, &nlen, &vcons) != 0)
                    return -1;
                newPinEnc = nv; newPinEnc_len = nlen;
                p += vcons; remain -= vcons;
                break;
            }
            case 6: { /* pinHashEnc */
                const uint8_t *hv; uint32_t hlen; uint16_t vcons;
                if (cbor_read_bytes(p, remain, &hv, &hlen, &vcons) != 0)
                    return -1;
                pinHashEnc = hv; pinHashEnc_len = hlen;
                p += vcons; remain -= vcons;
                break;
            }
            default: {
                uint16_t skip;
                if (cbor_skip(p, remain, &skip) != 0)
                    return -1;
                p += skip; remain -= skip;
                break;
            }
        }
    }

    if (pinProtocol != CTAP2_PIN_PROTOCOL_SUPPORTED) {
        reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0;
    }

    switch (subCmd) {
        case 1: { /* getRetries */
            struct cbor_buf c = {.buf = reply, .cap = reply_max, .len = 1};
            reply[0] = CTAP2_ERR_SUCCESS;
            if (cbor_start_map(&c, 1) != 0) return -1;
            if (cbor_put_uint(&c, 3) != 0) return -1; /* PIN_RETRIES */
            if (cbor_put_uint(&c, pin_store.retries) != 0) return -1;
            *reply_len = c.len;
            return 0;
        }
        case 2: { /* getKeyAgreement */
            wc_InitRng(&rng);
            if (pin_generate_agreement_key(&rng) != 0) {
                wc_FreeRng(&rng);
                reply[0] = CTAP2_ERR_INVALID_COMMAND; *reply_len = 1; return 0;
            }
            wc_FreeRng(&rng);
            struct cbor_buf c = {.buf = reply, .cap = reply_max, .len = 1};
            reply[0] = CTAP2_ERR_SUCCESS;
            if (cbor_start_map(&c, 1) != 0) return -1;
            if (cbor_put_uint(&c, 1) != 0) return -1;
            if (cbor_start_map(&c, 5) != 0) return -1;
            if (cbor_put_int(&c, COSE_KEY_KTY_LABEL) != 0) return -1;
            if (cbor_put_uint(&c, COSE_KTY_EC2) != 0) return -1;
            if (cbor_put_int(&c, COSE_KEY_ALG_LABEL) != 0) return -1;
            if (cbor_put_int(&c, COSE_ALG_ECDH_ES_HKDF256) != 0) return -1;
            if (cbor_put_int(&c, COSE_KEY_CRV_LABEL) != 0) return -1;
            if (cbor_put_uint(&c, COSE_CRV_P256) != 0) return -1;
            if (cbor_put_int(&c, COSE_KEY_X_LABEL) != 0) return -1;
            if (cbor_put_bytes(&c, pin_agree_qx, ECC_SZ) != 0) return -1;
            if (cbor_put_int(&c, COSE_KEY_Y_LABEL) != 0) return -1;
            if (cbor_put_bytes(&c, pin_agree_qy, ECC_SZ) != 0) return -1;
            *reply_len = c.len;
            return 0;
        }
        case 3: { /* setPIN */
            if (pin_store.magic == FLASH_PIN_MAGIC) {
                reply[0] = CTAP2_ERR_PIN_AUTH_INVALID; *reply_len = 1; return 0;
            }
            if (!key_agree || !pin_agree_valid || parse_cose_pubkey(key_agree, (uint16_t)key_agree_len, platform_qx, platform_qy) != 0) {
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
            struct cbor_buf c = {.buf = reply, .cap = reply_max, .len = 1};
            reply[0] = CTAP2_ERR_SUCCESS;
            if (cbor_start_map(&c, 0) != 0) return -1;
            *reply_len = c.len;
            return 0;
        }
        case 4: { /* changePIN */
            if (pin_store.magic != FLASH_PIN_MAGIC) {
                reply[0] = CTAP2_ERR_PIN_NOT_SET; *reply_len = 1; return 0;
            }
            if (pin_check_retries() != 0) {
                reply[0] = CTAP2_ERR_PIN_BLOCKED; *reply_len = 1; return 0;
            }
            if (!key_agree || !pin_agree_valid || parse_cose_pubkey(key_agree, (uint16_t)key_agree_len, platform_qx, platform_qy) != 0) {
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
            struct cbor_buf c = {.buf = reply, .cap = reply_max, .len = 1};
            reply[0] = CTAP2_ERR_SUCCESS;
            if (cbor_start_map(&c, 0) != 0) return -1;
            *reply_len = c.len;
            return 0;
        }
        case 5: { /* getPINToken */
            if (pin_store.magic != FLASH_PIN_MAGIC) {
                reply[0] = CTAP2_ERR_PIN_NOT_SET; *reply_len = 1; return 0;
            }
            if (pin_check_retries() != 0) {
                reply[0] = CTAP2_ERR_PIN_BLOCKED; *reply_len = 1; return 0;
            }
            if (!key_agree || !pin_agree_valid || parse_cose_pubkey(key_agree, (uint16_t)key_agree_len, platform_qx, platform_qy) != 0) {
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
                struct cbor_buf c = {.buf = reply, .cap = reply_max, .len = 1};
                reply[0] = CTAP2_ERR_SUCCESS;
                if (cbor_start_map(&c, 1) != 0) { wc_FreeRng(&rng); return -1; }
                if (cbor_put_uint(&c, 2) != 0) { wc_FreeRng(&rng); return -1; }
                if (cbor_put_bytes(&c, tmp, enc_len) != 0) { wc_FreeRng(&rng); return -1; }
                *reply_len = c.len;
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
