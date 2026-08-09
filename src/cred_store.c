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
#include "pico/stdlib.h"
#include "hardware/flash.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/chacha20_poly1305.h"
#include "wolfssl/wolfcrypt/kdf.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/puf.h"
#include "cred_store.h"
#include "device_state.h"
#include "flash_rt.h"

extern void ForceZero(void* mem, word32 len);

/* Reuses the sector that held the plaintext resident-key slots. */
#define FLASH_VAULT_OFF   0x74000
#define FLASH_VAULT_ADDR  ((const uint8_t *)(XIP_BASE + FLASH_VAULT_OFF))
#define VAULT_MAGIC       0x46564C54u /* 'FVLT' */

/* Header is stored in the clear; only `slots` is sealed.
 *
 * `version` is the key-derivation input and increases on every write, so each
 * save uses a key that has never been used before. That makes nonce reuse --
 * the failure mode that breaks Poly1305 catastrophically -- structurally
 * impossible rather than merely unlikely, and it means a key recovered from
 * one version is useless against any other.
 *
 * The header is passed as additional authenticated data so the ciphertext is
 * bound to the version it was sealed under. That is ordinary AEAD hygiene, not
 * rollback protection: an attacker who can rewrite flash already has physical
 * control of the device, which is a tamper-detection problem rather than a
 * cryptographic one.
 */
struct vault_header {
    uint32_t magic;
    uint32_t version;
    uint8_t  nonce[CHACHA20_POLY1305_AEAD_IV_SIZE];
    uint8_t  tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    uint16_t payload_len;
    uint8_t  reserved[2];
};

static struct cred_record slots[CRED_STORE_SLOTS];
static uint32_t vault_version;
static bool vault_loaded;

#define VAULT_PAYLOAD_SZ ((uint16_t)sizeof(slots))
#define VAULT_TOTAL_SZ   (sizeof(struct vault_header) + VAULT_PAYLOAD_SZ)

static int vault_key(uint32_t version, uint8_t *key_out)
{
    const uint8_t *secret = device_get_secret();
    uint8_t info[16 + 4];
    uint8_t ver_be[4];
    int ret;

    if (secret == NULL)
        return -1;
    ver_be[0] = (uint8_t)(version >> 24);
    ver_be[1] = (uint8_t)(version >> 16);
    ver_be[2] = (uint8_t)(version >> 8);
    ver_be[3] = (uint8_t)version;

    memcpy(info, "fidelio-rk-db", 13);
    memcpy(info + 13, ver_be, 4);

    ret = wc_HKDF_Expand(WC_SHA256, secret, WC_PUF_KEY_SZ, info, 13 + 4,
                         key_out, CHACHA20_POLY1305_AEAD_KEYSIZE);
    ForceZero(info, sizeof(info));
    return (ret == 0) ? 0 : -1;
}

int cred_store_load(void)
{
    const struct vault_header *h = (const struct vault_header *)FLASH_VAULT_ADDR;
    const uint8_t *ct = FLASH_VAULT_ADDR + sizeof(struct vault_header);
    uint8_t key[CHACHA20_POLY1305_AEAD_KEYSIZE];
    int ret;

    if (vault_loaded)
        return 0;

    memset(slots, 0, sizeof(slots));
    vault_version = 0;

    /* An absent or erased vault is simply an empty one. */
    if (h->magic != VAULT_MAGIC || h->payload_len != VAULT_PAYLOAD_SZ) {
        vault_loaded = true;
        return 0;
    }

    if (vault_key(h->version, key) != 0)
        return -1;

    ret = wc_ChaCha20Poly1305_Decrypt(key, h->nonce,
                                      (const byte *)h, offsetof(struct vault_header, tag),
                                      ct, VAULT_PAYLOAD_SZ,
                                      h->tag, (byte *)slots);
    ForceZero(key, sizeof(key));

    if (ret != 0) {
        /* Authentication failure: tampered, or sealed under a master secret
         * this device no longer has. Refuse to serve it rather than expose
         * whatever the plaintext buffer now holds.
         */
        memset(slots, 0, sizeof(slots));
        return -1;
    }

    vault_version = h->version;
    vault_loaded = true;
    return 0;
}

/* Static, not automatic: core 0's stack is 2 KB and this buffer is larger
 * than that. Scrubbed before every return.
 */
static uint8_t vault_page[VAULT_TOTAL_SZ];

static int vault_save(void)
{
    uint8_t *page = vault_page;
    struct vault_header *h = (struct vault_header *)page;
    uint8_t *ct = page + sizeof(struct vault_header);
    uint8_t key[CHACHA20_POLY1305_AEAD_KEYSIZE];
    WC_RNG rng;
    int ret = -1;

    memset(page, 0, sizeof(vault_page));
    h->magic = VAULT_MAGIC;
    h->version = vault_version + 1;
    h->payload_len = VAULT_PAYLOAD_SZ;

    if (wc_InitRng(&rng) != 0) {
        ForceZero(vault_page, sizeof(vault_page));
        return -1;
    }
    if (wc_RNG_GenerateBlock(&rng, h->nonce, sizeof(h->nonce)) != 0) {
        wc_FreeRng(&rng);
        ForceZero(vault_page, sizeof(vault_page));
        return -1;
    }
    wc_FreeRng(&rng);

    if (vault_key(h->version, key) != 0) {
        ForceZero(vault_page, sizeof(vault_page));
        return -1;
    }

    ret = wc_ChaCha20Poly1305_Encrypt(key, h->nonce,
                                      (const byte *)h, offsetof(struct vault_header, tag),
                                      (const byte *)slots, VAULT_PAYLOAD_SZ,
                                      ct, h->tag);
    ForceZero(key, sizeof(key));
    if (ret != 0) {
        ForceZero(vault_page, sizeof(vault_page));
        return -1;
    }

    fidelio_flash_erase(FLASH_VAULT_OFF, FLASH_SECTOR_SIZE);
    fidelio_flash_program(FLASH_VAULT_OFF, page, sizeof(vault_page));
    ForceZero(vault_page, sizeof(vault_page));

    vault_version++;
    return 0;
}

int cred_store_put(const struct cred_record *rec)
{
    int free_slot = -1;
    unsigned i;

    if (rec == NULL)
        return -1;
    if (cred_store_load() != 0)
        return -1;

    /* One credential per (relying party, user): re-registering the same
     * account replaces it rather than accumulating duplicates. */
    for (i = 0; i < CRED_STORE_SLOTS; i++) {
        if (slots[i].cred_id_len == 0) {
            if (free_slot < 0)
                free_slot = (int)i;
            continue;
        }
        if (memcmp(slots[i].rp_id_hash, rec->rp_id_hash, 32) == 0 &&
            slots[i].user_id_len == rec->user_id_len &&
            memcmp(slots[i].user_id, rec->user_id, rec->user_id_len) == 0) {
            free_slot = (int)i;
            break;
        }
    }
    if (free_slot < 0)
        return -1; /* full */

    slots[free_slot] = *rec;
    return vault_save();
}

const struct cred_record *cred_store_get(const uint8_t *rp_id_hash,
                                         unsigned index)
{
    unsigned i, seen = 0;

    if (cred_store_load() != 0)
        return NULL;
    for (i = 0; i < CRED_STORE_SLOTS; i++) {
        if (slots[i].cred_id_len == 0)
            continue;
        if (memcmp(slots[i].rp_id_hash, rp_id_hash, 32) != 0)
            continue;
        if (seen == index)
            return &slots[i];
        seen++;
    }
    return NULL;
}

unsigned cred_store_count(const uint8_t *rp_id_hash)
{
    unsigned i, n = 0;

    if (cred_store_load() != 0)
        return 0;
    for (i = 0; i < CRED_STORE_SLOTS; i++) {
        if (slots[i].cred_id_len != 0 &&
            memcmp(slots[i].rp_id_hash, rp_id_hash, 32) == 0)
            n++;
    }
    return n;
}

void cred_store_wipe(void)
{
    ForceZero(slots, sizeof(slots));
    vault_version = 0;
    vault_loaded = false;
    fidelio_flash_erase(FLASH_VAULT_OFF, FLASH_SECTOR_SIZE);
}
