#ifndef CTAP2_H
#define CTAP2_H

#include <stdint.h>

/* Handle CTAP2 CBOR requests. Returns 0 on successful reply generation. */
int ctap2_handle_cbor(const uint8_t *payload, uint16_t payload_len,
                      uint8_t *reply, uint16_t reply_max, uint16_t *reply_len);

#endif /* CTAP2_H */
