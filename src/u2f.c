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

#include <stdint.h>
#include <string.h>
#include "pico/stdlib.h"
#include "hardware/gpio.h"
#include "hardware/flash.h"
#include "bsp/board.h"
#include "class/hid/hid.h"
#include "class/hid/hid_device.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "cert.h"
#include "pins.h"


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
#define FLASH_MKEY_OFF      0x72000
#define FLASH_MKEY ((uint32_t *)(XIP_BASE + FLASH_MKEY_OFF))
#define FLASH_CTR0 *((uint32_t *)(XIP_BASE + FLASH_CTR_ADDR0_OFF))
#define FLASH_CTR1 *((uint32_t *)(XIP_BASE + FLASH_CTR_ADDR1_OFF))

static uint32_t master_magic = 0xF1D091C0;

static uint8_t *device_secret = (uint8_t *)(FLASH_MKEY + 4);
static uint32_t *magic_check = (uint32_t *)FLASH_MKEY;

static uint32_t U2F_Counter = 0;

static void flash_master_keygen(void)
{
    WC_RNG rng;
    uint8_t mkey_buffer[4 + 32];
    gpio_put(U2F_LED, 1);
    wc_InitRng(&rng);
    wc_RNG_GenerateBlock(&rng, mkey_buffer, 32);
    flash_range_erase(FLASH_MKEY_OFF, FLASH_SECTOR_SIZE);
    flash_range_erase(FLASH_CTR_ADDR0_OFF, FLASH_SECTOR_SIZE);
    flash_range_erase(FLASH_CTR_ADDR1_OFF, FLASH_SECTOR_SIZE);
    flash_range_program(FLASH_CTR_ADDR0_OFF, (void *)&U2F_Counter, 4);
    flash_range_program(FLASH_MKEY_OFF, (void *)&master_magic, 4);
    flash_range_program(FLASH_MKEY_OFF + 4, mkey_buffer, 32);
    wc_FreeRng(&rng);
    gpio_put(U2F_LED, 0);
}

static void U2F_Counter_up(void)
{
    U2F_Counter++;
    if ((U2F_Counter & 0x01) == 0x01) {
        flash_range_program(FLASH_CTR_ADDR1_OFF, (void *)&U2F_Counter, 4);
        flash_range_erase(FLASH_CTR_ADDR0_OFF, FLASH_SECTOR_SIZE);
    } else {
        flash_range_program(FLASH_CTR_ADDR0_OFF, (void *)&U2F_Counter, 4);
        flash_range_erase(FLASH_CTR_ADDR1_OFF, FLASH_SECTOR_SIZE);
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
    if (*magic_check != master_magic) {
        flash_master_keygen();
        U2F_Counter = 0;
    } else {
        U2F_Counter = U2F_Counter_load();
    }
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

#define RESPONSE_MAX_SIZE 2048

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

static int u2fhid_sendmsg(uint16_t sz, int err)
{
    uint8_t u2h_msg[U2FHID_PACKET_SIZE];
    struct u2fhid_init_packet *ip;
    uint32_t len;

    memset(u2h_msg, 0, U2FHID_PACKET_SIZE);
    U2F_cmd_reply_sent = 0;
    U2F_cmd_reply_seq = 0;
    if (err) {
        U2F_cmd_reply_size = sz;
    } else {
        U2F_cmd_reply_size = sz + 2;
        U2F_cmd_reply[sz] = 0x90;
        U2F_cmd_reply[sz + 1] = 0x00;
    }

    ip = (struct u2fhid_init_packet *)u2h_msg;
    ip->cid = 0;
    ip->hid_cmd = 0x80 | CTAP_CMD_MSG;
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
    word32 inOutIdx = 0;
    uint32_t idx = 0;
    uint8_t *challenge, *application;
    ecc_key user_ecc;
    ecc_key cert_ecc;
    WC_RNG rng;
    challenge = U2F_Message.data + sizeof(struct u2f_raw_hdr);
    application = U2F_Message.data + sizeof(struct u2f_raw_hdr) + PARAM_SZ;
    (void)hdr;
    (void)len;


    gpio_put(U2F_LED, 1);
    while(1) {
        sleep_ms(2);
        if (gpio_get(PRESENCE_BUTTON) == 0) {
            break;
        }
    }
    gpio_put(U2F_LED, 0);

    /* Initialize wolfCrypt objects */
    if (wc_InitRng(&rng) != 0)
        return 0x6110;
    if (wc_ecc_init(&user_ecc) != 0)
        return 0x6111;
    if (wc_ecc_init(&cert_ecc) != 0)
        return 0x6111;

    /* Import certificate private key */
    if (wc_EccPrivateKeyDecode(cert_master_key_der, &inOutIdx, &cert_ecc, cert_master_key_der_len) != 0) {
        return 0x6113;
    }
    
    /* Check imported key */
    if (wc_ecc_check_key(&cert_ecc) != 0) {
        return 0x6118;
    }
    

    /* Calculate private key (nonce + application) */ 
    ret = wc_HmacInit(&hmac, NULL, 0);
    if (ret != 0)
        return 0x6114;
    ret = wc_RNG_GenerateBlock(&rng, handle_nonce, NONCE_SZ);
    if (ret != 0)
        return 0x6114;
    ret = wc_HmacSetKey(&hmac, SHA256, device_secret, ECC_SZ); 
    if (ret != 0)
        return 0x6116;
    wc_HmacUpdate(&hmac, application, PARAM_SZ);
    wc_HmacUpdate(&hmac, handle_nonce, NONCE_SZ);
    wc_HmacFinal(&hmac, user_private);
    wc_HmacFree(&hmac);

    /* Calculate user handle (private + application) */
    ret = wc_HmacInit(&hmac, NULL, 0);
    if (ret != 0)
        return 0x6114;
    ret = wc_HmacSetKey(&hmac, SHA256, device_secret, ecc_key_size); 
    if (ret != 0)
        return 0x6116;
    wc_HmacUpdate(&hmac, application, PARAM_SZ);
    wc_HmacUpdate(&hmac, user_private, ECC_SZ);
    wc_HmacFinal(&hmac, handle_hash);
    wc_HmacFree(&hmac);
    if (wc_ecc_import_private_key_ex(user_private, ecc_key_size, NULL, 0,
                &user_ecc, ECC_SECP256R1) != 0)
        return 0x6111;
    ret = wc_ecc_make_pub_ex(&user_ecc, NULL, NULL); 
    /* At this point the user key should be complete. */
    if (wc_ecc_check_key(&user_ecc) != 0) {
        return 0x6118;
    }
    /* Export public key */
    pubkey[0] = 0x04; /* First byte 0x04 indicating uncompressed 
                       *  public key (qx, qy) 
                       */
    ret = wc_ecc_export_public_raw(&user_ecc, &pubkey[1], &qxlen,
            &pubkey[1 + ecc_key_size], &qylen); 
    if (ret != 0)
        return 0x6113;

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

    /* Sign the digest */
    memset(signature, 0, sizeof(signature));
    siglen = (word32)wc_ecc_sig_size(&cert_ecc);
    ret = wc_ecc_sign_hash(sig_hash, HASH_SZ, signature, &siglen, &rng,
            &cert_ecc);
    
    U2F_Counter_up();

    /* Populate reply message
     */
    U2F_cmd_reply[idx++] = 0x05; /* Legacy fixed first byte for the response */
    memcpy(&U2F_cmd_reply[idx], pubkey, PUBKEY_SZ);
    idx += PUBKEY_SZ;
    /* Copy key handle (nonce + hash) into reply */
    U2F_cmd_reply[idx++] = NONCE_SZ + HASH_SZ; /* Size of the handle */
    memcpy(&U2F_cmd_reply[idx], handle_nonce, NONCE_SZ);
    idx += NONCE_SZ;
    memcpy(&U2F_cmd_reply[idx], handle_hash, HASH_SZ);
    idx += HASH_SZ;
    /* Copy attestation certificate into reply */
    memcpy(&U2F_cmd_reply[idx], cert_att_der, cert_att_der_len);
    idx += cert_att_der_len;
    /* Copy signature */
    memcpy(&U2F_cmd_reply[idx], signature, siglen);
    idx += siglen;
    /* Send the reply */
    u2fhid_sendmsg((uint16_t)idx, 0);
    wc_FreeRng(&rng);
    wc_ecc_free(&user_ecc);
    wc_ecc_free(&cert_ecc);
    ForceZero(&user_ecc, sizeof(ecc_key));
    ForceZero(&cert_ecc, sizeof(ecc_key));
    ForceZero(user_private, ECC_SZ);
    return ENOERR;
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
    ecc_key user_ecc;
    WC_RNG rng;
    Hmac hmac;
    Sha256 sha;
    int ret;

    (void)len;
    msg_data = U2F_Message.data + sizeof(struct u2f_raw_hdr);
    control = hdr->p1;
    challenge = msg_data;
    application = msg_data + PARAM_SZ;
    handle_sz = msg_data[PARAM_SZ + PARAM_SZ];
    handle_nonce = msg_data + PARAM_SZ + PARAM_SZ + 1;
    handle_hash = msg_data + PARAM_SZ + PARAM_SZ + 1 + NONCE_SZ;

    switch (control) {
        case 0x07: /* "check-only" */
        case 0x08: /* Sign with no presence */
            break;
        case 0x03:
            gpio_put(U2F_LED, 1);
            while(1) {
                sleep_ms(2);
                if (gpio_get(PRESENCE_BUTTON) == 0) {
                    user_presence = 0x01;
                    break;
                }
            }
            gpio_put(U2F_LED, 0);
            break;
        default:
            return EWRONGDATA;
    }

    if (wc_InitRng(&rng) != 0)
        return 0x6110;

    if (wc_ecc_init(&user_ecc) < 0)
        return 0x6122;

    if (handle_sz != (NONCE_SZ + HASH_SZ))
        return 0x6120;

    ret = wc_HmacInit(&hmac, NULL, 0);
    if (ret != 0)
        return 0x6124;
    ret = wc_HmacSetKey(&hmac, SHA256, device_secret, ECC_SZ); 
    if (ret != 0)
        return 0x6126;
    wc_HmacUpdate(&hmac, application, PARAM_SZ);
    wc_HmacUpdate(&hmac, handle_nonce, NONCE_SZ);
    wc_HmacFinal(&hmac, private);
    wc_HmacFree(&hmac);

    /* Verify obtained hash */
    ret = wc_HmacInit(&hmac, NULL, 0);
    if (ret != 0)
        return 0x6124;
    ret = wc_HmacSetKey(&hmac, SHA256, device_secret, ECC_SZ); 
    if (ret != 0)
        return 0x6126;
    wc_HmacUpdate(&hmac, application, PARAM_SZ);
    wc_HmacUpdate(&hmac, private, ECC_SZ);
    wc_HmacFinal(&hmac, handle_calculated_hash);
    wc_HmacFree(&hmac);
    if (memcmp(handle_calculated_hash, handle_hash, HASH_SZ) != 0)
        return EWRONGDATA;

    if (wc_ecc_import_private_key_ex(private, ECC_SZ, NULL, 0,
                &user_ecc, ECC_SECP256R1) != 0)
        return 0x6121;
    ret = wc_ecc_make_pub_ex(&user_ecc, NULL, NULL); 
    /* At this point the user key should be complete. */
    if (wc_ecc_check_key(&user_ecc) != 0) {
        return 0x6128;
    }

    if (control == 0x07) {
        return ECOND;
    }

    be_u2f_counter = __builtin_bswap32(U2F_Counter);
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, application, PARAM_SZ);       /* Application parameter */
    wc_Sha256Update(&sha, &user_presence, 1);           /* User presence byte */
    wc_Sha256Update(&sha, (void*)&be_u2f_counter, 4);   /* Usage counter */
    wc_Sha256Update(&sha, challenge, PARAM_SZ);         /* Challenge parameter */
    wc_Sha256Final(&sha, sig_hash);
    wc_Sha256Free(&sha);
    
    /* Sign the digest */
    memset(signature, 0, sizeof(signature));
    siglen = (uint16_t)wc_ecc_sig_size(&user_ecc);
    ret = wc_ecc_sign_hash(sig_hash, HASH_SZ, signature, &siglen, &rng,
            &user_ecc);

    memset(U2F_cmd_reply, 0, sizeof(U2F_cmd_reply));
    U2F_cmd_reply[0] = user_presence;
    memcpy(&U2F_cmd_reply[1], &be_u2f_counter, 4);
    memcpy(&U2F_cmd_reply[1 + 4], signature, siglen);

    U2F_Counter_up();

    /* Send the reply */
    u2fhid_sendmsg((uint16_t)(siglen + 5), 0);
    wc_FreeRng(&rng);
    wc_ecc_free(&user_ecc);
    ForceZero(&user_ecc, sizeof(ecc_key));
    ForceZero(private, ECC_SZ);
    return ENOERR;
}

static uint16_t fido_getversion(struct u2f_raw_hdr *hdr, uint16_t len)
{
    const char proto_name[] = "U2F_V2";
    uint8_t reply[U2FHID_PACKET_SIZE];
    struct u2fhid_init_packet *ip = (struct u2fhid_init_packet *)reply;
    (void)hdr;
    (void)len;
    ip->cid = 0;
    ip->hid_cmd = CTAP_CMD_MSG;
    ip->payload_len[0] = 0;
    ip->payload_len[1] = 8;
    memcpy(reply + 7, proto_name, 6);
    reply[14] = 0x90;
    reply[15] = 0x00;
    tud_hid_report(0, reply, U2FHID_PACKET_SIZE);
    return 0x9000;
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
        default:
            return EINSUNSUPP;
    }
    U2F_Message.len = 0;
    return 0x9000;
}

static void ctap_init_reply(void)
{
    uint8_t reply[U2FHID_PACKET_SIZE];
    memcpy(reply, &U2F_Message.cid, sizeof(uint32_t));
    reply[4] = CTAP_CMD_INIT | 0x80; 
    reply[5] = 0x00; /* Len MSB */
    reply[6] = 17;   /* Len LSB */
    memcpy(reply + 7, U2F_Message.data, 8);
    memset(reply + 15, 0, 4);
    reply[19] = 1; /* Fido Protocol version */
    reply[20] = 1; /* Maj V*/
    reply[21] = 0; /* Min V*/
    reply[22] = 0; /* Build V */
    reply[23] = 0; /* cap flags, 1 for wink */
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
                u2fhid_sendmsg(2, 1);
                ret = ENOERR;
            }
            break;
        default:
            return EWRONGDATA;
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
        if (len > U2FHID_MAX_PAYLOAD)
            return EWRONGLEN;

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

        /* If we are received the wrong sequence, discard. */
        if (cp->seq != U2F_Message.exp_seq) {
            U2F_Message.len = 0;
            return 0;
        }
        U2F_Message.exp_seq++;

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
        uint16_t ret = parse_u2f_raw();
        if (ret != ENOERR) {
            uint8_t reply[U2FHID_PACKET_SIZE];
            memset(&U2F_Message, 0, sizeof(struct u2f_message));
            reply[0] = (uint8_t)(ret & 0xFF00U) >> 8U;
            reply[1] = ret & 0xFFU;
            tud_hid_report(0, reply, U2FHID_PACKET_SIZE);
        }
    }
    return 0;
}

/* SET_REPORT is called with ID=0 and Type=0 when receiving data
 * on the 'OUT' endpoint
 */
void tud_hid_set_report_cb(uint8_t itf, uint8_t report_id, hid_report_type_t report_type, uint8_t const* buffer, uint16_t bufsize)
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

void tud_hid_report_complete_cb(uint8_t instance, const uint8_t *report,
        uint8_t len)
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
        u2h_msg[4] = (uint8_t)(U2F_cmd_reply_seq & 0xFFU);
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
