#ifndef FDO_H
#define FDO_H

#include <stdint.h>

typedef enum {
    FDO_STATE_DI = 0,
    FDO_STATE_TO0,
    FDO_STATE_TO1,
    FDO_STATE_TO2,
    FDO_STATE_DONE,
} fdo_state_t;

void fdo_init(void);
fdo_state_t fdo_get_state(void);
int fdo_set_state(fdo_state_t st);
int fdo_store_voucher_hash(const uint8_t *hash, uint16_t len);
int fdo_store_owner_pub(const uint8_t *pub, uint16_t len);

#endif /* FDO_H */
