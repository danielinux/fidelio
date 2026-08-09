/* Fidelio
 *
 * (c) 2023 Daniele Lacamera <root@danielinux.net>
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

/* Two sectors, written alternately. A sector must be erased before it can be
 * reprogrammed, and a power cut inside that window would otherwise destroy the
 * only copy of every discoverable credential. Alternating means the previous
 * sealed copy survives; the AEAD tag already rejects a half-written one, so no
 * separate integrity marker is needed here.
 */
#define FLASH_VAULT_A_OFF 0x74000
#define FLASH_VAULT_B_OFF 0x77000
#define VAULT_ADDR(off)   ((const uint8_t *)(XIP_BASE + (off)))
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
static uint32_t vault_cur_off = FLASH_VAULT_A_OFF;

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

/* Try one sector. Returns 0 and fills `slots` if it authenticates. */
static int vault_try(uint32_t off)
{
    const struct vault_header *h = (const struct vault_header *)VAULT_ADDR(off);
    const uint8_t *ct = VAULT_ADDR(off) + sizeof(struct vault_header);
    uint8_t key[CHACHA20_POLY1305_AEAD_KEYSIZE];
    int ret;

    if (h->magic != VAULT_MAGIC || h->payload_len != VAULT_PAYLOAD_SZ)
        return -1;
    if (vault_key(h->version, key) != 0)
        return -1;

    ret = wc_ChaCha20Poly1305_Decrypt(key, h->nonce,
                                      (const byte *)h, offsetof(struct vault_header, tag),
                                      ct, VAULT_PAYLOAD_SZ,
                                      h->tag, (byte *)slots);
    ForceZero(key, sizeof(key));
    if (ret != 0) {
        /* Tampered, torn mid-write, or sealed under a master secret this
         * device no longer has. Never serve a partially decrypted buffer. */
        memset(slots, 0, sizeof(slots));
        return -1;
    }
    return 0;
}

int cred_store_load(void)
{
    const struct vault_header *ha = (const struct vault_header *)VAULT_ADDR(FLASH_VAULT_A_OFF);
    const struct vault_header *hb = (const struct vault_header *)VAULT_ADDR(FLASH_VAULT_B_OFF);
    uint32_t first, second;

    if (vault_loaded)
        return 0;

    memset(slots, 0, sizeof(slots));
    vault_version = 0;

    /* Newest first, falling back to the older copy if the newest is torn. */
    if (ha->magic == VAULT_MAGIC && hb->magic == VAULT_MAGIC) {
        bool a_newer = (int32_t)(ha->version - hb->version) > 0;
        first = a_newer ? FLASH_VAULT_A_OFF : FLASH_VAULT_B_OFF;
        second = a_newer ? FLASH_VAULT_B_OFF : FLASH_VAULT_A_OFF;
    } else {
        first = (ha->magic == VAULT_MAGIC) ? FLASH_VAULT_A_OFF : FLASH_VAULT_B_OFF;
        second = (first == FLASH_VAULT_A_OFF) ? FLASH_VAULT_B_OFF : FLASH_VAULT_A_OFF;
    }

    if (vault_try(first) == 0) {
        vault_cur_off = first;
    } else if (vault_try(second) == 0) {
        vault_cur_off = second;
    } else {
        /* Neither copy is usable. An absent vault is simply an empty one. */
        vault_cur_off = FLASH_VAULT_B_OFF; /* first save lands in A */
        vault_loaded = true;
        return 0;
    }

    vault_version = ((const struct vault_header *)VAULT_ADDR(vault_cur_off))->version;
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

    {
        uint32_t target = (vault_cur_off == FLASH_VAULT_A_OFF)
                          ? FLASH_VAULT_B_OFF : FLASH_VAULT_A_OFF;
        fidelio_flash_erase(target, FLASH_SECTOR_SIZE);
        fidelio_flash_program(target, page, sizeof(vault_page));
        vault_cur_off = target;
    }
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

    /* One discoverable credential per relying party, replacing any previous
     * one for that site.
     *
     * Fidelio is a personal authenticator holding a single identity, so
     * "another account on the same site" is not a supported case. Enforcing
     * that here keeps numberOfCredentials at one for every assertion, which
     * is what makes authenticatorGetNextAssertion (0x08) unnecessary rather
     * than merely unimplemented: the platform only issues it when the
     * authenticator reports more than one credential.
     *
     * The trade-off is deliberate and worth knowing: registering a second
     * account at a site that already has a credential replaces the first,
     * and access to the earlier account is lost. Non-discoverable
     * credentials are unaffected -- the relying party names which one it
     * wants in the allowList, so any number may coexist.
     */
    for (i = 0; i < CRED_STORE_SLOTS; i++) {
        if (slots[i].cred_id_len == 0) {
            if (free_slot < 0)
                free_slot = (int)i;
            continue;
        }
        if (memcmp(slots[i].rp_id_hash, rec->rp_id_hash, 32) == 0) {
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
    fidelio_flash_erase(FLASH_VAULT_A_OFF, FLASH_SECTOR_SIZE);
    fidelio_flash_erase(FLASH_VAULT_B_OFF, FLASH_SECTOR_SIZE);
    vault_cur_off = FLASH_VAULT_B_OFF;
}
