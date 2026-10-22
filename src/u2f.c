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

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "pico/stdlib.h"
#include "hardware/gpio.h"
#include "hardware/flash.h"
#include "hardware/watchdog.h"
#include "bsp/board.h"
#include "class/hid/hid.h"
#include "class/hid/hid_device.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "att.h"
#include "ctap2.h"
#include "device_state.h"
#include "pins.h"
#include "flash_rt.h"
#include "indicator.h"
#include "fdo.h"
#include "puf_sram.h"


#define PUBKEY_SZ 65
#define PARAM_SZ  32
#define ECC_SZ    32
#define SIGMAX_SZ 75
#define HASH_SZ   32
#define NONCE_SZ  32


#define U2FHID_PACKET_SIZE 64
#define U2FHID_MAX_PAYLOAD (U2FHID_PACKET_SIZE - 7 + 128 * (U2FHID_PACKET_SIZE - 5)) /* = 7609 bytes */

extern void ForceZero(void* mem, word32 len);

#define FLASH_CTR_ADDR0_OFF 0x70000
#define FLASH_CTR_ADDR1_OFF 0x71000
/* 0x72000 holds the SRAM PUF checkpoint; see src/puf_sram.c. It used to hold
 * the master key itself, which is no longer stored anywhere.
 */
#define FLASH_CTR0 *((uint32_t *)(XIP_BASE + FLASH_CTR_ADDR0_OFF))
#define FLASH_CTR1 *((uint32_t *)(XIP_BASE + FLASH_CTR_ADDR1_OFF))

/* Reconstructed from the SRAM PUF at boot, never written to flash. */
#define device_secret (puf_master_secret())

static uint32_t U2F_Counter = 0;

static void write_counter_page(uint32_t flash_off, uint32_t value)
{
    uint8_t page_buf[FLASH_PAGE_SIZE];
    memcpy(page_buf, (const void *)(XIP_BASE + flash_off), FLASH_PAGE_SIZE);
    memcpy(page_buf, &value, 4);
    fidelio_flash_program(flash_off, page_buf, FLASH_PAGE_SIZE);
}

static void __not_in_flash_func(U2F_Counter_up)(void)
{
    U2F_Counter++;
    if ((U2F_Counter & 0x01) == 0x01) {
        write_counter_page(FLASH_CTR_ADDR1_OFF, U2F_Counter);
        fidelio_flash_erase(FLASH_CTR_ADDR0_OFF, FLASH_SECTOR_SIZE);
    } else {
        write_counter_page(FLASH_CTR_ADDR0_OFF, U2F_Counter);
        fidelio_flash_erase(FLASH_CTR_ADDR1_OFF, FLASH_SECTOR_SIZE);
    }
}

static uint32_t U2F_Counter_load(void)
{
    uint32_t a, b;
    a = FLASH_CTR0;
    b = FLASH_CTR1;
    if ((a == 0xFFFFFFFF) && b == (0xFFFFFFFF))
        return 0;
    else if (a == 0xFFFFFFFF)
        return b;
    else if (b == 0xFFFFFFFF)
        return a;
    else if (b > a)
        return b;
    else
        return a;
}

void u2f_init(void)
{
    /* The master secret is already reconstructed by puf_provision(), which
     * runs before this and does not return unless it succeeded.
     */
    U2F_Counter = U2F_Counter_load();
}

void __not_in_flash_func(u2f_factory_reset)(void)
{
    /* Turn LED yellow while wiping state */
    indicator_set(0x20, 0x20, 0);
    /* Dropping the PUF checkpoint is what actually invalidates credentials.
     * The next boot enrolls again and draws a fresh salt, so the new master
     * secret is unrelated to the old one even though the SRAM response is
     * replayed unchanged across the warm reset below.
     */
    puf_factory_erase();
    fidelio_flash_erase(FLASH_CTR_ADDR0_OFF, FLASH_SECTOR_SIZE);
    fidelio_flash_erase(FLASH_CTR_ADDR1_OFF, FLASH_SECTOR_SIZE);
    ctap2_reset_state();
    fdo_reset();
    U2F_Counter = 0;
    indicator_set_idle();
    watchdog_reboot(0, 0, 0);
    while (1) { tight_loop_contents(); }
}



struct __attribute__((packed)) u2fhid_init_packet {
    uint32_t cid;
    uint8_t hid_cmd;
    uint8_t payload_len[2];
    uint8_t data[U2FHID_PACKET_SIZE - 7];
};

struct __attribute__((packed)) u2fhid_cont_packet {
    uint32_t cid;
    uint8_t seq; /* sequence number, 0-127 */
    uint8_t data[U2FHID_PACKET_SIZE - 5];
};

struct __attribute__((packed)) u2fhid_generic_packet {
    uint32_t cid;
    uint8_t select;
};


struct u2f_message {
    uint32_t cid;
    uint8_t cmd;
    uint16_t len;
    uint16_t rx_len;
    uint8_t exp_seq;
    uint8_t data[U2FHID_MAX_PAYLOAD];
};


struct __attribute__((packed)) u2f_raw_hdr {
    uint8_t cla;
    uint8_t ins;
    uint8_t p1, p2;
    uint8_t len[3];
};

#define U2F_REGISTER_INS 0x01
#define U2F_AUTHENTICATE_INS 0x02
#define U2F_VERSION_INS 0x03

/* Authentication data flags. */
#define CTAP_AUTHDATA_USER_PRESENT	0x01
#define CTAP_AUTHDATA_USER_VERIFIED	0x04
#define CTAP_AUTHDATA_ATT_CRED		0x40
#define CTAP_AUTHDATA_EXT_DATA		0x80

/* CTAPHID command opcodes. */
#define CTAP_CMD_PING			0x01
#define CTAP_CMD_MSG			0x03
#define CTAP_CMD_LOCK			0x04
#define CTAP_CMD_INIT			0x06
#define CTAP_CMD_WINK			0x08
#define CTAP_CMD_CBOR			0x10
#define CTAP_CMD_CANCEL			0x11
#define CTAP_KEEPALIVE			0x3b
#define CTAP_FRAME_INIT			0x80

/* Must hold the largest CTAP2 reply. An ML-DSA-87 assertion is a 4627-byte
 * signature plus authData and the credential descriptor; a makeCredential
 * carries a 2592-byte public key inside authData plus the attestation
 * certificate. 8 KiB covers both and still fits the CTAPHID ceiling of 7609
 * payload bytes per message.
 */
#define RESPONSE_MAX_SIZE CTAP2_MAX_MSG_SIZE

#define VALID_CID 0x00000000


#define ENOERR 0x9000
#define ECOND  0x6985
#define EWRONGDATA 0x6A80
#define EWRONGLEN  0x6700
#define ECLAUNSUPP 0x6E00
#define EINSUNSUPP 0x6D00

static struct u2f_message U2F_Message;
static uint8_t U2F_cmd_reply[RESPONSE_MAX_SIZE];
static uint32_t U2F_cmd_reply_sent = 0;
static uint32_t U2F_cmd_reply_size = 0;
static uint32_t U2F_cmd_reply_seq = 0;
static uint32_t U2F_cmd_reply_cid = 0;

static int ctaphid_send(uint8_t cmd, uint16_t sz, bool append_status_word)
{
    uint8_t u2h_msg[U2FHID_PACKET_SIZE];
    struct u2fhid_init_packet *ip;
    uint32_t len;

    memset(u2h_msg, 0, U2FHID_PACKET_SIZE);
    U2F_cmd_reply_sent = 0;
    U2F_cmd_reply_seq = 0;
    if (append_status_word) {
        U2F_cmd_reply_size = sz + 2;
        U2F_cmd_reply[sz] = 0x90;
        U2F_cmd_reply[sz + 1] = 0x00;
    } else {
        U2F_cmd_reply_size = sz;
    }

    ip = (struct u2fhid_init_packet *)u2h_msg;
    ip->cid = U2F_Message.cid;
    U2F_cmd_reply_cid = U2F_Message.cid;
    ip->hid_cmd = 0x80 | cmd;
    ip->payload_len[0] = ((U2F_cmd_reply_size) & 0xFF00) >> 8;
    ip->payload_len[1] = (U2F_cmd_reply_size) & 0xFF;
    len = U2FHID_PACKET_SIZE - 7;
    if (U2F_cmd_reply_size < len)
        len = U2F_cmd_reply_size;
    memcpy(u2h_msg + 7, U2F_cmd_reply, len);
    tud_hid_report(0, u2h_msg, U2FHID_PACKET_SIZE);
    U2F_cmd_reply_sent = len;
    return 0;
}

/* CTAPHID error codes (CTAP 2.x, section 11.2.9.1.6). */
#define CTAPHID_ERROR           0x3F
#define CTAPHID_ERR_INVALID_CMD 0x01
#define CTAPHID_ERR_INVALID_LEN 0x03
#define CTAPHID_ERR_OTHER       0x7F

/* Send a well-formed CTAPHID ERROR frame. The whole 64-byte report is zeroed
 * first: the previous error path sent an uninitialised stack buffer, which
 * disclosed 62 bytes of stack to any process with access to the HID node.
 * The global continuation state is dropped too: without it, a reply that was
 * mid-flight would keep streaming its stale frames after this error.
 */
static void ctaphid_send_error(uint32_t cid, uint8_t err)
{
    uint8_t frame[U2FHID_PACKET_SIZE];

    U2F_cmd_reply_sent = 0;
    U2F_cmd_reply_size = 0;
    U2F_cmd_reply_seq = 0;
    memset(frame, 0, sizeof(frame));
    memcpy(frame, &cid, sizeof(cid));
    frame[4] = 0x80 | CTAPHID_ERROR;
    frame[5] = 0x00;                 /* payload length, MSB */
    frame[6] = 0x01;                 /* payload length, LSB */
    frame[7] = err;
    tud_hid_report(0, frame, sizeof(frame));
}

/* P-256 group order. A 256-bit HMAC output is a valid private scalar only
 * below this, which fails with probability ~2^-32. The output is always
 * less than 2n, so the reduction is one conditional subtraction; it is the
 * identity for every scalar that was already valid, so existing credentials
 * are untouched.
 */
static const uint8_t P256_ORDER[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
};

static bool constant_time_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

static void p256_reduce_scalar(uint8_t *s)
{
    uint32_t i;
    uint32_t a, sub, borrow;
    /* ge starts true so s == n counts as >= n and reduces to 0, which the
     * key import then rejects; every other case is decided by the first
     * differing byte. */
    int ge = 1;

    for (i = 0; i < 32; i++) {
        if (s[i] != P256_ORDER[i]) {
            ge = (s[i] > P256_ORDER[i]) ? 1 : 0;
            break;
        }
    }
    if (!ge)
        return;
    borrow = 0;
    for (i = 32; i > 0; i--) {
        a = s[i - 1];
        sub = P256_ORDER[i - 1] + borrow;
        borrow = (a < sub) ? 1 : 0;
        s[i - 1] = (uint8_t)(a - sub);
    }
}

static uint16_t fido_register(struct u2f_raw_hdr *hdr, uint16_t len)
{
    uint8_t sig_hash[HASH_SZ];
    uint8_t handle_nonce[HASH_SZ];
    uint8_t handle_hash[HASH_SZ];
    word32 ecc_key_size = ECC_SZ;
    word32 qxlen = ECC_SZ;
    word32 qylen = ECC_SZ;
    word32 siglen = SIGMAX_SZ;
    Hmac hmac;
    wc_Sha256 sha;
    int ret;
    uint8_t signature[SIGMAX_SZ]; /* Large enough to contain ecc256 signature */
    uint8_t rfu_res = 0;
    uint8_t pubkey[PUBKEY_SZ];
    uint8_t user_private[ECC_SZ];
    uint32_t idx = 0;
    uint8_t *challenge, *application;
    const uint8_t *att_der;
    uint32_t att_der_len = 0;
    uint16_t sw = 0x6111;
    ecc_key user_ecc;
    ecc_key cert_ecc;
    WC_RNG rng;
    challenge = U2F_Message.data + sizeof(struct u2f_raw_hdr);
    application = U2F_Message.data + sizeof(struct u2f_raw_hdr) + PARAM_SZ;
    /* Zeroed so the cleanup path can free them on every route, including
     * one that failed before the initialiser ran. */
    memset(&user_ecc, 0, sizeof(user_ecc));
    memset(&cert_ecc, 0, sizeof(cert_ecc));
    (void)hdr;
    if (len != PARAM_SZ * 2)
        return EWRONGLEN;

    if (!indicator_wait_for_button(0, 0x20, 0))
        return ECOND;

    /* Initialize wolfCrypt objects */
    if (wc_InitRng(&rng) != 0)
        return 0x6110;
    if (wc_ecc_init(&user_ecc) != 0)
        goto cleanup;

    /* Per-device attestation key and certificate, both derived from the PUF
     * secret (src/att.c). att_key_init() initialises cert_ecc itself and
     * leaves it zeroed on failure, which is safe to free below.
     */
    if (att_key_init(&cert_ecc) != 0) {
        sw = 0x6113;
        goto cleanup;
    }
    if (att_cert_get(&rng, &att_der, &att_der_len) != 0) {
        sw = 0x6113;
        goto cleanup;
    }

    /* Calculate private key (nonce + application) */
    ret = wc_HmacInit(&hmac, NULL, 0);
    if (ret != 0) {
        sw = 0x6114;
        goto cleanup;
    }
    ret = wc_RNG_GenerateBlock(&rng, handle_nonce, NONCE_SZ);
    if (ret != 0) {
        sw = 0x6114;
        goto cleanup;
    }
    ret = wc_HmacSetKey(&hmac, SHA256, device_secret, ECC_SZ);
    if (ret != 0) {
        sw = 0x6116;
        goto cleanup;
    }
    wc_HmacUpdate(&hmac, application, PARAM_SZ);
    wc_HmacUpdate(&hmac, handle_nonce, NONCE_SZ);
    wc_HmacFinal(&hmac, user_private);
    wc_HmacFree(&hmac);
    /* The raw HMAC output reaches the curve order with probability ~2^-32;
     * reduce it so registration cannot fail on scalar range. */
    p256_reduce_scalar(user_private);

    /* Calculate user handle (private + application) */
    ret = wc_HmacInit(&hmac, NULL, 0);
    if (ret != 0) {
        sw = 0x6114;
        goto cleanup;
    }
    ret = wc_HmacSetKey(&hmac, SHA256, device_secret, ecc_key_size);
    if (ret != 0) {
        sw = 0x6116;
        goto cleanup;
    }
    wc_HmacUpdate(&hmac, application, PARAM_SZ);
    wc_HmacUpdate(&hmac, user_private, ECC_SZ);
    wc_HmacFinal(&hmac, handle_hash);
    wc_HmacFree(&hmac);
    if (wc_ecc_import_private_key_ex(user_private, ecc_key_size, NULL, 0,
                &user_ecc, ECC_SECP256R1) != 0)
        goto cleanup;
    ret = wc_ecc_make_pub_ex(&user_ecc, NULL, NULL);
    /* At this point the user key should be complete. */
    if (wc_ecc_check_key(&user_ecc) != 0) {
        sw = 0x6118;
        goto cleanup;
    }
    /* Export public key */
    pubkey[0] = 0x04; /* First byte 0x04 indicating uncompressed
                       *  public key (qx, qy)
                       */
    ret = wc_ecc_export_public_raw(&user_ecc, &pubkey[1], &qxlen,
            &pubkey[1 + ecc_key_size], &qylen);
    if (ret != 0) {
        sw = 0x6113;
        goto cleanup;
    }

    /* Prepare the digest to sign */
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, &rfu_res, 1); /* RFU = 0 */
    wc_Sha256Update(&sha, application, PARAM_SZ); /* Application parameter */
    wc_Sha256Update(&sha, challenge, PARAM_SZ); /* Challenge parameter */
    wc_Sha256Update(&sha, handle_nonce, NONCE_SZ); /* handle: nonce part */
    wc_Sha256Update(&sha, handle_hash, HASH_SZ); /* handle: hash part */
    wc_Sha256Update(&sha, pubkey, PUBKEY_SZ); /* Public key */
    wc_Sha256Final(&sha, sig_hash);
    wc_Sha256Free(&sha);

    /* Sign the digest; a failure must not burn the usage counter. */
    memset(signature, 0, sizeof(signature));
    siglen = (word32)wc_ecc_sig_size(&cert_ecc);
    if (wc_ecc_sign_hash(sig_hash, HASH_SZ, signature, &siglen, &rng,
            &cert_ecc) != 0) {
        sw = 0x6113;
        goto cleanup;
    }

    /* Populate reply message */
    U2F_cmd_reply[idx++] = 0x05; /* Legacy fixed first byte for the response */
    memcpy(&U2F_cmd_reply[idx], pubkey, PUBKEY_SZ);
    idx += PUBKEY_SZ;
    /* Copy key handle (nonce + hash) into reply */
    U2F_cmd_reply[idx++] = NONCE_SZ + HASH_SZ; /* Size of the handle */
    memcpy(&U2F_cmd_reply[idx], handle_nonce, NONCE_SZ);
    idx += NONCE_SZ;
    memcpy(&U2F_cmd_reply[idx], handle_hash, HASH_SZ);
    idx += HASH_SZ;
    /* Copy attestation certificate into reply. Its length is decided at
     * runtime now, so check it against the buffer rather than trusting a
     * compile-time constant; the +2 is the 0x9000 status word
     * ctaphid_send() appends.
     */
    if (idx + att_der_len + siglen + 2 > sizeof(U2F_cmd_reply)) {
        sw = 0x6113;
        goto cleanup;
    }
    memcpy(&U2F_cmd_reply[idx], att_der, att_der_len);
    idx += att_der_len;
    /* Copy signature */
    memcpy(&U2F_cmd_reply[idx], signature, siglen);
    idx += siglen;
    U2F_Counter_up();
    /* Send the reply */
    ctaphid_send(CTAP_CMD_MSG, (uint16_t)idx, true);
    sw = ENOERR;

cleanup:
    wc_FreeRng(&rng);
    wc_ecc_free(&user_ecc);
    wc_ecc_free(&cert_ecc);
    ForceZero(&user_ecc, sizeof(ecc_key));
    ForceZero(&cert_ecc, sizeof(ecc_key));
    ForceZero(user_private, ECC_SZ);
    return sw;
}



static uint16_t fido_auth(struct u2f_raw_hdr *hdr, uint16_t len)
{
    uint8_t *challenge, *application, *handle_nonce, *handle_hash;
    uint8_t private[ECC_SZ], handle_calculated_hash[HASH_SZ];
    uint8_t control = 0, handle_sz = 0, user_presence = 0;
    uint8_t sig_hash[HASH_SZ], signature[SIGMAX_SZ];
    uint32_t be_u2f_counter;
    word32 siglen = SIGMAX_SZ;
    uint8_t *msg_data;
    uint16_t sw = EWRONGDATA;
    ecc_key user_ecc;
    WC_RNG rng;
    Hmac hmac;
    Sha256 sha;
    int ret;

    if (len < PARAM_SZ * 2 + 1)
        return EWRONGLEN;
    msg_data = U2F_Message.data + sizeof(struct u2f_raw_hdr);
    control = hdr->p1;
    challenge = msg_data;
    application = msg_data + PARAM_SZ;
    handle_sz = msg_data[PARAM_SZ + PARAM_SZ];
    if (handle_sz != NONCE_SZ + HASH_SZ || len != PARAM_SZ * 2 + 1 + handle_sz)
        return EWRONGLEN;
    handle_nonce = msg_data + PARAM_SZ + PARAM_SZ + 1;
    handle_hash = msg_data + PARAM_SZ + PARAM_SZ + 1 + NONCE_SZ;
    /* Zeroed so the cleanup path can free it on every route, including one
     * that failed before the initialiser ran. */
    memset(&user_ecc, 0, sizeof(user_ecc));

    if (control != 0x07 && control != 0x03)
        return EWRONGDATA;

    if (wc_InitRng(&rng) != 0)
        return 0x6110;

    if (wc_ecc_init(&user_ecc) != 0) {
        sw = 0x6122;
        goto cleanup;
    }

    if (handle_sz != (NONCE_SZ + HASH_SZ)) {
        sw = 0x6120;
        goto cleanup;
    }

    ret = wc_HmacInit(&hmac, NULL, 0);
    if (ret != 0) {
        sw = 0x6124;
        goto cleanup;
    }
    ret = wc_HmacSetKey(&hmac, SHA256, device_secret, ECC_SZ);
    if (ret != 0) {
        sw = 0x6126;
        goto cleanup;
    }
    wc_HmacUpdate(&hmac, application, PARAM_SZ);
    wc_HmacUpdate(&hmac, handle_nonce, NONCE_SZ);
    wc_HmacFinal(&hmac, private);
    wc_HmacFree(&hmac);
    /* Same reduction as fido_register(): the stored handle was computed
     * from the reduced scalar. */
    p256_reduce_scalar(private);

    /* Verify obtained hash */
    ret = wc_HmacInit(&hmac, NULL, 0);
    if (ret != 0) {
        sw = 0x6124;
        goto cleanup;
    }
    ret = wc_HmacSetKey(&hmac, SHA256, device_secret, ECC_SZ);
    if (ret != 0) {
        sw = 0x6126;
        goto cleanup;
    }
    wc_HmacUpdate(&hmac, application, PARAM_SZ);
    wc_HmacUpdate(&hmac, private, ECC_SZ);
    wc_HmacFinal(&hmac, handle_calculated_hash);
    wc_HmacFree(&hmac);
    if (!constant_time_equal(handle_calculated_hash, handle_hash, HASH_SZ))
        goto cleanup;

    if (wc_ecc_import_private_key_ex(private, ECC_SZ, NULL, 0,
                &user_ecc, ECC_SECP256R1) != 0) {
        sw = 0x6121;
        goto cleanup;
    }
    ret = wc_ecc_make_pub_ex(&user_ecc, NULL, NULL);
    /* At this point the user key should be complete. */
    if (wc_ecc_check_key(&user_ecc) != 0) {
        sw = 0x6128;
        goto cleanup;
    }

    if (control == 0x07) {
        sw = ECOND;
        goto cleanup;
    }

    /* Only a valid handle may request presence. Invalid handles should not
     * light the button or make the user wait. */
    if (!indicator_wait_for_button(0, 0, 0x20)) {
        sw = ECOND;
        goto cleanup;
    }
    user_presence = 0x01;

    be_u2f_counter = __builtin_bswap32(U2F_Counter);
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, application, PARAM_SZ);       /* Application parameter */
    wc_Sha256Update(&sha, &user_presence, 1);           /* User presence byte */
    wc_Sha256Update(&sha, (void*)&be_u2f_counter, 4);   /* Usage counter */
    wc_Sha256Update(&sha, challenge, PARAM_SZ);         /* Challenge parameter */
    wc_Sha256Final(&sha, sig_hash);
    wc_Sha256Free(&sha);

    /* Sign the digest; a failure must not burn the usage counter. */
    memset(signature, 0, sizeof(signature));
    siglen = (uint16_t)wc_ecc_sig_size(&user_ecc);
    if (wc_ecc_sign_hash(sig_hash, HASH_SZ, signature, &siglen, &rng,
            &user_ecc) != 0) {
        sw = 0x6121;
        goto cleanup;
    }

    memset(U2F_cmd_reply, 0, sizeof(U2F_cmd_reply));
    U2F_cmd_reply[0] = user_presence;
    memcpy(&U2F_cmd_reply[1], &be_u2f_counter, 4);
    memcpy(&U2F_cmd_reply[1 + 4], signature, siglen);

    U2F_Counter_up();

    /* Send the reply */
    ctaphid_send(CTAP_CMD_MSG, (uint16_t)(siglen + 5), true);
    sw = ENOERR;

cleanup:
    wc_FreeRng(&rng);
    wc_ecc_free(&user_ecc);
    ForceZero(&user_ecc, sizeof(ecc_key));
    ForceZero(private, ECC_SZ);
    return sw;
}

static uint16_t fido_getversion(struct u2f_raw_hdr *hdr, uint16_t len)
{
    static const char proto_name[] = "U2F_V2";
    (void)hdr;
    (void)len;
    /* Reply through the common path so the frame is fully zero-padded and
     * carries the caller's CID, then append SW 0x9000. */
    memcpy(U2F_cmd_reply, proto_name, sizeof(proto_name) - 1);
    ctaphid_send(CTAP_CMD_MSG, (uint16_t)(sizeof(proto_name) - 1), true);
    return ENOERR;
}

static uint16_t parse_u2f_raw_msg(void)
{
    struct u2f_raw_hdr *hdr = (struct u2f_raw_hdr *)(U2F_Message.data);
    uint32_t len = U2F_Message.len - sizeof(struct u2f_raw_hdr);


    if (U2F_Message.len < sizeof(struct u2f_raw_hdr))
        return EWRONGLEN;
    if (U2F_Message.len > U2FHID_MAX_PAYLOAD)
        return EWRONGLEN;
    if (hdr->cla != 0x00)
        return ECLAUNSUPP;
    switch(hdr->ins) {
        case U2F_REGISTER_INS:
            return fido_register(hdr, (uint16_t)len);
        case U2F_AUTHENTICATE_INS:
            return fido_auth(hdr, (uint16_t)len);
        case U2F_VERSION_INS:
            return fido_getversion(hdr, (uint16_t)len);
        case CTAP_CMD_CBOR:
            /* Should not reach here: CBOR handled at HID layer */
            return EINSUNSUPP;
        default:
            return EINSUNSUPP;
    }
    U2F_Message.len = 0;
    return 0x9000;
}

const uint8_t *device_get_secret(void)
{
    return device_secret;
}

uint32_t device_get_counter(void)
{
    return U2F_Counter;
}

void device_counter_inc(void)
{
    U2F_Counter_up();
}

static void ctap_init_reply(void)
{
    uint8_t reply[U2FHID_PACKET_SIZE];
    memset(reply, 0, sizeof(reply));
    memcpy(reply, &U2F_Message.cid, sizeof(uint32_t));
    reply[4] = CTAP_CMD_INIT | 0x80; 
    reply[5] = 0x00; /* Len MSB */
    reply[6] = 17;   /* Len LSB */
    memcpy(reply + 7, U2F_Message.data, 8);
    memset(reply + 15, 0, 4);
    reply[19] = 2; /* CTAPHID protocol version */
    reply[20] = 2; /* Maj V*/
    reply[21] = 0; /* Min V*/
    reply[22] = 0; /* Build V */
    reply[23] = 0x05; /* cap flags: wink + CBOR */
    tud_hid_report(0, reply, U2FHID_PACKET_SIZE);
}

static uint16_t parse_u2f_raw(void)
{
    uint16_t ret;
    switch (U2F_Message.cmd) {
        case CTAP_CMD_INIT:
            ctap_init_reply();
            return ENOERR;
        case CTAP_CMD_MSG:
            ret =  parse_u2f_raw_msg();
            if (ret != ENOERR) {
                uint8_t err[2];
                memcpy(err, &ret, 2);
                U2F_cmd_reply[0] = err[1];
                U2F_cmd_reply[1] = err[0];
                ctaphid_send(CTAP_CMD_MSG, 2, false);
                ret = ENOERR;
            }
            break;
        case CTAP_CMD_CBOR: {
            uint16_t reply_len = 0;
            int ctap2_ret = ctap2_handle_cbor(U2F_Message.data, U2F_Message.len, U2F_cmd_reply, sizeof(U2F_cmd_reply), &reply_len);
            if (ctap2_ret == 0 && reply_len > 0) {
                ctaphid_send(CTAP_CMD_CBOR, reply_len, false);
                ret = ENOERR;
            } else {
                ctaphid_send_error(U2F_Message.cid, CTAPHID_ERR_OTHER);
                ret = ENOERR;
            }
            break;
        }
        default:
            ctaphid_send_error(U2F_Message.cid, CTAPHID_ERR_INVALID_CMD);
            return ENOERR;
    }
    return ret;
}

int parse_u2fhid_packet(const uint8_t *data)
{
    const struct u2fhid_generic_packet *gp =
        (const struct u2fhid_generic_packet *)data;

    if ((gp->select & 0x80) == 0x80) {
        const struct u2fhid_init_packet *ip;
        uint16_t len;
        /* Init packet. Start a new buffer. */
        ip = (const struct u2fhid_init_packet *)gp;
        len = (uint16_t)((uint16_t)(ip->payload_len[0]) << 8U) + ip->payload_len[1];
        if (len > U2FHID_MAX_PAYLOAD) {
            ctaphid_send_error(ip->cid, CTAPHID_ERR_INVALID_LEN);
            return EWRONGLEN;
        }

        memset(&U2F_Message, 0, sizeof(struct u2f_message));
        U2F_Message.len = len;
        memcpy(&U2F_Message.cid, &ip->cid, sizeof(uint32_t)); 
        U2F_Message.cmd = ip->hid_cmd & 0x7F;
        memcpy(U2F_Message.data, ip->data, U2FHID_PACKET_SIZE - 7);
        U2F_Message.rx_len = U2FHID_PACKET_SIZE - 7;
        U2F_Message.exp_seq = 0;
    } else {
        /* Continuation packet */
        const struct u2fhid_cont_packet *cp;
        uint16_t sz_rx;
        cp = (const struct u2fhid_cont_packet *)gp;

        /* If no init packet received, discard. */
        if (U2F_Message.len == 0)
            return 0;

        /* A continuation from another channel cannot alter this request. */
        if (cp->cid != U2F_Message.cid)
            return 0;

        /* If we are received the wrong sequence, discard. */
        if (cp->seq != U2F_Message.exp_seq) {
            U2F_Message.len = 0;
            return 0;
        }
        U2F_Message.exp_seq++;
        if (U2F_Message.exp_seq >= 128)
            U2F_Message.exp_seq = 0;

        sz_rx = U2FHID_PACKET_SIZE - 5;
        if (sz_rx > (U2F_Message.len - U2F_Message.rx_len))
            sz_rx = U2F_Message.len - U2F_Message.rx_len;
        memcpy(U2F_Message.data + U2F_Message.rx_len, cp->data, sz_rx);
        U2F_Message.rx_len += sz_rx;
    }
    if (U2F_Message.rx_len > U2F_Message.len)
        U2F_Message.rx_len = U2F_Message.len;
    if (U2F_Message.rx_len == U2F_Message.len) {
        /* Finally parse the raw packet */
        uint32_t cid = U2F_Message.cid;
        uint16_t ret = parse_u2f_raw();
        /* The request is complete, even when its response spans frames. */
        U2F_Message.len = 0;
        if (ret != ENOERR) {
            /* Defensive: parse_u2f_raw() now reports its own errors, so this
             * should not trigger. Never send an unformatted buffer here. */
            memset(&U2F_Message, 0, sizeof(struct u2f_message));
            ctaphid_send_error(cid, CTAPHID_ERR_OTHER);
        }
    }
    return 0;
}

/* SET_REPORT is called with ID=0 and Type=0 when receiving data
 * on the 'OUT' endpoint
 */
void tud_hid_set_report_cb(uint8_t itf, uint8_t report_id, hid_report_type_t report_type, const uint8_t * buffer, uint16_t bufsize)
{
    (void) itf;
    (void) report_id;
    (void) report_type;

    if (bufsize != U2FHID_PACKET_SIZE)
        return;
    parse_u2fhid_packet(buffer);
    
}


uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type, uint8_t* buffer, uint16_t reqlen)
{
  (void) instance;
  (void) report_id;
  (void) report_type;
  (void) buffer;
  (void) reqlen;

  return 0;
}

void tud_hid_report_complete_cb(uint8_t instance, uint8_t const* report, uint8_t len)
{
    (void) instance;
    (void) len;
    (void) report;


    if (U2F_cmd_reply_size == 0)
        return;
    /* Continue sending if there are
     * any pending u2f reply, spanning over multiple frames 
     */
    if (U2F_cmd_reply_sent < U2F_cmd_reply_size) {
        uint16_t remain_size;
        uint8_t u2h_msg[U2FHID_PACKET_SIZE];
        memset(u2h_msg, 0, U2FHID_PACKET_SIZE);
        memcpy(u2h_msg, &U2F_cmd_reply_cid, sizeof(U2F_cmd_reply_cid));
        /* 7-bit sequence, wraps at 128 per CTAPHID. */
        u2h_msg[4] = (uint8_t)(U2F_cmd_reply_seq & 0x7FU);
        U2F_cmd_reply_seq++;
        remain_size = U2FHID_PACKET_SIZE - 5;
        if (remain_size > U2F_cmd_reply_size - U2F_cmd_reply_sent)
            remain_size = (uint16_t)(U2F_cmd_reply_size - U2F_cmd_reply_sent);
        memcpy(u2h_msg + 5, U2F_cmd_reply + U2F_cmd_reply_sent, remain_size); 
        U2F_cmd_reply_sent += remain_size;
        tud_hid_report(0, u2h_msg, U2FHID_PACKET_SIZE);
    } else {
        U2F_cmd_reply_sent = 0;
        U2F_cmd_reply_size = 0;
        U2F_cmd_reply_seq = 0;
    }
}
