/* Verify that wolfCOSE's COSE_Key encoding is byte-identical to the CBOR
 * that Fidelio's hand-rolled encode_cose_pubkey() used to emit, and that
 * wolfCOSE's decoder accepts what the old parse_cose_pubkey() accepted.
 *
 * Old encoder emitted, in this exact order:
 *   map(5), 1:2, 3:-7, -1:1, -2:bstr(32) qx, -3:bstr(32) qy
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfcose/wolfcose.h>

#define ECC_SZ 32

static void hexdump(const char *tag, const uint8_t *b, size_t n);

#include <stdlib.h>
int host_random_seed(unsigned char *out, unsigned int sz)
{
    static int seeded = 0;
    if (!seeded) { srand(1234); seeded = 1; }
    for (unsigned int i = 0; i < sz; i++)
        out[i] = (unsigned char)(rand() & 0xFF);
    return 0;
}

/* --- verbatim copy of the pre-port encoder from src/ctap2.c --- */
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
static int cbor_put_uint(struct cbor_buf *b, uint32_t v) { return cbor_put_type_val(b, 0, v); }
static int cbor_put_int(struct cbor_buf *b, int32_t v)
{
    if (v < 0) return cbor_put_type_val(b, 1, (uint32_t)(-1 - v));
    return cbor_put_uint(b, (uint32_t)v);
}
static int cbor_put_bytes(struct cbor_buf *b, const uint8_t *d, uint16_t len)
{
    if (cbor_put_type_val(b, 2, len) != 0) return -1;
    if (b->len + len > b->cap) return -1;
    memcpy(&b->buf[b->len], d, len);
    b->len += len;
    return 0;
}
static int cbor_start_map(struct cbor_buf *b, uint8_t n) { return cbor_put_type_val(b, 5, n); }

static int old_encode_cose_pubkey(struct cbor_buf *c, const uint8_t *qx,
                                  const uint8_t *qy, int32_t alg)
{
    if (cbor_start_map(c, 5) != 0) return -1;
    if (cbor_put_int(c, 1) != 0) return -1;
    if (cbor_put_uint(c, 2) != 0) return -1;
    if (cbor_put_int(c, 3) != 0) return -1;
    if (cbor_put_int(c, alg) != 0) return -1;
    if (cbor_put_int(c, -1) != 0) return -1;
    if (cbor_put_uint(c, 1) != 0) return -1;
    if (cbor_put_int(c, -2) != 0) return -1;
    if (cbor_put_bytes(c, qx, ECC_SZ) != 0) return -1;
    if (cbor_put_int(c, -3) != 0) return -1;
    if (cbor_put_bytes(c, qy, ECC_SZ) != 0) return -1;
    return 0;
}

/* --- the ported encoder, verbatim shape of src/ctap2.c now --- */
static int cose_encode_from_key(uint8_t *out, size_t outSz, size_t *outLen,
                                ecc_key *ecc, int32_t alg)
{
    WOLFCOSE_KEY key;

    if (wc_CoseKey_Init(&key) != WOLFCOSE_SUCCESS) return -1;
    if (wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, ecc) != WOLFCOSE_SUCCESS) return -1;
    key.alg = alg;
    if (wc_CoseKey_Encode_ex(&key, out, outSz, outLen,
                             WOLFCOSE_KEY_PUBLIC_ONLY) != WOLFCOSE_SUCCESS)
        return -1;
    return 0;
}

/* Helper for cases that only have raw coordinates. No ecc_key is needed to
 * serialise them, so this is an independent path to the same bytes.
 */
static int new_encode_cose_pubkey(uint8_t *out, size_t outSz, size_t *outLen,
                                  const uint8_t *qx, const uint8_t *qy,
                                  int32_t alg)
{
    if (wc_CoseKey_EncodeEccRaw(WOLFCOSE_CRV_P256, qx, qy, NULL, ECC_SZ,
                                NULL, 0, alg, out, outSz,
                                outLen) != WOLFCOSE_SUCCESS)
        return -1;
    return 0;
}

/* The real hot path: encode straight from a key that still holds its private
 * scalar. Must produce public-only output, identical to the raw-coordinate
 * path, and must never contain the private scalar d.
 */
static int check_private_key_not_leaked(WC_RNG *rng)
{
    ecc_key k;
    uint8_t qx[ECC_SZ], qy[ECC_SZ], d[ECC_SZ];
    word32 xl = ECC_SZ, yl = ECC_SZ, dl = ECC_SZ;
    uint8_t from_priv[160], from_pub[160];
    size_t lp = 0, lq = 0;
    int bad = 0;

    if (wc_ecc_init(&k) != 0) return 1;
    if (wc_ecc_make_key_ex(rng, ECC_SZ, &k, ECC_SECP256R1) != 0) { wc_ecc_free(&k); return 1; }
    if (k.type != ECC_PRIVATEKEY) {
        printf("FAIL: test key is not a private key, check is vacuous\n");
        wc_ecc_free(&k);
        return 1;
    }
    wc_ecc_export_public_raw(&k, qx, &xl, qy, &yl);
    wc_ecc_export_private_only(&k, d, &dl);

    if (cose_encode_from_key(from_priv, sizeof(from_priv), &lp, &k, -7) != 0) {
        printf("FAIL: encode from private key\n"); wc_ecc_free(&k); return 1;
    }
    wc_ecc_free(&k);

    if (new_encode_cose_pubkey(from_pub, sizeof(from_pub), &lq, qx, qy, -7) != 0) {
        printf("FAIL: encode from raw coords\n"); return 1;
    }
    if (lp != lq || memcmp(from_priv, from_pub, lp) != 0) {
        printf("FAIL: private-key path differs from public path\n");
        hexdump("  priv", from_priv, lp);
        hexdump("  pub ", from_pub, lq);
        bad = 1;
    }
    /* The private scalar must not appear anywhere in the output. */
    for (size_t i = 0; dl <= lp && i + dl <= lp; i++) {
        if (memcmp(from_priv + i, d, dl) == 0) {
            printf("FAIL: private scalar present in COSE_Key output at %zu\n", i);
            bad = 1;
            break;
        }
    }
    /* kty, alg, crv, x, y = map(5). A leaked d would make it map(6) = 0xa6. */
    if (from_priv[0] != 0xa5) {
        printf("FAIL: expected map(5) header 0xa5, got 0x%02x\n", from_priv[0]);
        bad = 1;
    }
    if (!bad)
        printf("private-key path emits public-only COSE_Key (%zu bytes, hdr 0x%02x)\n",
               lp, from_priv[0]);
    return bad;
}

/* --- the ported decoder, same shape as src/ctap2.c now --- */
static int new_parse_cose_pubkey(const uint8_t *buf, uint16_t len,
                                 uint8_t *qx, uint8_t *qy)
{
    WOLFCOSE_KEY key;
    ecc_key ecc;
    word32 qxlen = ECC_SZ, qylen = ECC_SZ;
    int ret = -1;

    if (wc_ecc_init(&ecc) != 0) return -1;
    if (wc_CoseKey_Init(&key) != WOLFCOSE_SUCCESS) goto out;
    if (wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &ecc) != WOLFCOSE_SUCCESS) goto out;
    if (wc_CoseKey_Decode(&key, buf, len) != WOLFCOSE_SUCCESS) goto out;
    if (key.kty != WOLFCOSE_KTY_EC2 || key.crv != WOLFCOSE_CRV_P256) goto out;
    if (key.alg != 0 && key.alg != -25 && key.alg != -7) goto out;
    if (wc_ecc_export_public_raw(&ecc, qx, &qxlen, qy, &qylen) != 0) goto out;
    if (qxlen != ECC_SZ || qylen != ECC_SZ) goto out;
    ret = 0;
out:
    wc_ecc_free(&ecc);
    return ret;
}

static void hexdump(const char *tag, const uint8_t *b, size_t n)
{
    printf("%s (%zu): ", tag, n);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

static int failures = 0;

static void run_case(WC_RNG *rng, int32_t alg, int iter)
{
    ecc_key k;
    uint8_t qx[ECC_SZ], qy[ECC_SZ];
    word32 qxlen = ECC_SZ, qylen = ECC_SZ;
    uint8_t oldbuf[128], newbuf[128];
    struct cbor_buf ob = { oldbuf, sizeof(oldbuf), 0 };
    size_t newlen = 0;

    if (wc_ecc_init(&k) != 0 ||
        wc_ecc_make_key_ex(rng, ECC_SZ, &k, ECC_SECP256R1) != 0 ||
        wc_ecc_export_public_raw(&k, qx, &qxlen, qy, &qylen) != 0) {
        printf("FAIL: keygen (iter %d)\n", iter);
        failures++;
        return;
    }
    wc_ecc_free(&k);

    if (old_encode_cose_pubkey(&ob, qx, qy, alg) != 0) {
        printf("FAIL: old encoder (iter %d)\n", iter); failures++; return;
    }
    if (new_encode_cose_pubkey(newbuf, sizeof(newbuf), &newlen, qx, qy, alg) != 0) {
        printf("FAIL: new encoder (iter %d)\n", iter); failures++; return;
    }
    if (newlen != ob.len || memcmp(newbuf, oldbuf, newlen) != 0) {
        printf("FAIL: wire mismatch alg=%d iter=%d\n", alg, iter);
        hexdump("  old", oldbuf, ob.len);
        hexdump("  new", newbuf, newlen);
        failures++;
        return;
    }

    /* Round-trip: the new decoder must recover the same coordinates from the
     * bytes the OLD encoder produced (what deployed clients send back). */
    uint8_t rx[ECC_SZ], ry[ECC_SZ];
    if (new_parse_cose_pubkey(oldbuf, ob.len, rx, ry) != 0) {
        printf("FAIL: new decoder rejected old-encoder bytes (iter %d)\n", iter);
        failures++;
        return;
    }
    if (memcmp(rx, qx, ECC_SZ) != 0 || memcmp(ry, qy, ECC_SZ) != 0) {
        printf("FAIL: decoded coordinates differ (iter %d)\n", iter);
        failures++;
        return;
    }

    if (iter == 0) {
        printf("alg=%-4d ok, wire: ", alg);
        for (size_t i = 0; i < newlen; i++) printf("%02x", newbuf[i]);
        printf("\n");
    }
}

int main(void)
{
    WC_RNG rng;

    if (wc_InitRng(&rng) != 0) {
        printf("FAIL: rng init\n");
        return 1;
    }

    /* Structural check against the literal CTAP2 expectation. */
    {
        uint8_t qx[ECC_SZ], qy[ECC_SZ], buf[128];
        size_t len = 0;
        ecc_key k;
        word32 xl = ECC_SZ, yl = ECC_SZ;
        wc_ecc_init(&k);
        wc_ecc_make_key_ex(&rng, ECC_SZ, &k, ECC_SECP256R1);
        wc_ecc_export_public_raw(&k, qx, &xl, qy, &yl);
        wc_ecc_free(&k);
        if (new_encode_cose_pubkey(buf, sizeof(buf), &len, qx, qy, -7) != 0) {
            printf("FAIL: structural encode\n");
            failures++;
        } else {
            const uint8_t want_hdr[] = { 0xa5, 0x01, 0x02, 0x03, 0x26,
                                         0x20, 0x01, 0x21, 0x58, 0x20 };
            if (len != 77 || memcmp(buf, want_hdr, sizeof(want_hdr)) != 0 ||
                memcmp(buf + 10, qx, ECC_SZ) != 0 ||
                buf[42] != 0x22 || buf[43] != 0x58 || buf[44] != 0x20 ||
                memcmp(buf + 45, qy, ECC_SZ) != 0) {
                printf("FAIL: structural layout\n");
                hexdump("  got", buf, len);
                failures++;
            } else {
                printf("structural ES256 COSE_Key layout ok (77 bytes)\n");
            }
        }
    }

    for (int i = 0; i < 8; i++)
        failures += check_private_key_not_leaked(&rng);

    for (int i = 0; i < 64; i++) {
        run_case(&rng, -7, i);   /* ES256, credential public key */
        run_case(&rng, -25, i);  /* ECDH-ES+HKDF-256, getKeyAgreement */
    }

    wc_FreeRng(&rng);

    if (failures == 0) {
        printf("ALL PASS\n");
        return 0;
    }
    printf("%d FAILURES\n", failures);
    return 1;
}
