#ifndef DEVICE_STATE_H
#define DEVICE_STATE_H

#include <stdint.h>

const uint8_t *device_get_secret(void);
uint32_t device_get_counter(void);
void device_counter_inc(void);

#endif /* DEVICE_STATE_H */
