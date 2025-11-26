/* FDO minimal state and storage scaffolding.
 *
 * Stores onboarding state, voucher hash, and owner public key material
 * in flash so DI/TO flows can be layered in subsequently.
 */

#include <string.h>
#include "hardware/flash.h"
#include "pico/stdlib.h"
#include "fdo.h"

#define FLASH_FDO_OFF 0x75000
#define FLASH_FDO_MAGIC 0x46444F21 /* 'FDO!' */

struct fdo_flash {
    uint32_t magic;
    uint8_t state;
    uint8_t voucher_hash[32];
    uint8_t owner_pub[64];
    uint16_t owner_pub_len;
};

static struct fdo_flash fdo_store;
static bool fdo_loaded = false;

static void fdo_save(void)
{
    flash_range_erase(FLASH_FDO_OFF, FLASH_SECTOR_SIZE);
    flash_range_program(FLASH_FDO_OFF, (const uint8_t *)&fdo_store, sizeof(fdo_store));
}

void fdo_init(void)
{
    if (fdo_loaded)
        return;
    const struct fdo_flash *flash = (const struct fdo_flash *)(XIP_BASE + FLASH_FDO_OFF);
    if (flash->magic == FLASH_FDO_MAGIC) {
        memcpy(&fdo_store, flash, sizeof(fdo_store));
    } else {
        memset(&fdo_store, 0, sizeof(fdo_store));
        fdo_store.magic = FLASH_FDO_MAGIC;
        fdo_store.state = FDO_STATE_DI;
        fdo_save();
    }
    fdo_loaded = true;
}

fdo_state_t fdo_get_state(void)
{
    fdo_init();
    return (fdo_state_t)fdo_store.state;
}

int fdo_set_state(fdo_state_t st)
{
    fdo_init();
    fdo_store.state = (uint8_t)st;
    fdo_save();
    return 0;
}

int fdo_store_voucher_hash(const uint8_t *hash, uint16_t len)
{
    fdo_init();
    if (len == 0 || len > sizeof(fdo_store.voucher_hash))
        return -1;
    memset(fdo_store.voucher_hash, 0, sizeof(fdo_store.voucher_hash));
    memcpy(fdo_store.voucher_hash, hash, len);
    fdo_save();
    return 0;
}

int fdo_store_owner_pub(const uint8_t *pub, uint16_t len)
{
    fdo_init();
    if (len == 0 || len > sizeof(fdo_store.owner_pub))
        return -1;
    memset(fdo_store.owner_pub, 0, sizeof(fdo_store.owner_pub));
    memcpy(fdo_store.owner_pub, pub, len);
    fdo_store.owner_pub_len = len;
    fdo_save();
    return 0;
}
