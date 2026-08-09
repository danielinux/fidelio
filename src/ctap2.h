#ifndef CTAP2_H
#define CTAP2_H

#include <stdint.h>

/* Largest CTAP2 message Fidelio will build or accept. Sized for an ML-DSA-87
 * assertion (4627-byte signature) and a makeCredential carrying a 2592-byte
 * public key; still inside the CTAPHID per-message ceiling of 7609 bytes.
 */
#define CTAP2_MAX_MSG_SIZE 8192

/* Handle CTAP2 CBOR requests. Returns 0 on successful reply generation. */
int ctap2_handle_cbor(const uint8_t *payload, uint16_t payload_len,
                      uint8_t *reply, uint16_t reply_max, uint16_t *reply_len);
void ctap2_reset_state(void);

#endif /* CTAP2_H */
