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

/* user_settings.h for wolfcrypt */

#ifndef H_USER_SETTINGS_
#define H_USER_SETTINGS_

/* System */

#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SINGLE_THREADED
#define WOLFCRYPT_ONLY
#define TFM_TIMING_RESISTANT
#define HAVE_SHA256
#define HAVE_SHA512
#define WOLFSSL_SHA512
#define WOLFSSL_SHA384
#define HAVE_HASHDRBG
#define HAVE_HKDF

/* Signature algorithms offered to relying parties.
 *
 * CTAP2 credential keys are all derived from the same 32 bytes coming out of
 * HMAC(master_secret, rpIdHash || nonce): ECDSA takes them as a scalar,
 * Ed25519 as its seed, ML-DSA via wc_MlDsaKey_MakeKeyFromSeed(). Nothing is
 * stored per algorithm, so breadth here costs code space and time, not state.
 */

/* EdDSA (COSE -8 / Ed25519 -19). ED25519_SMALL is deliberately NOT set: it
 * selects the size-optimised ge_low_mem backend, which is markedly slower.
 * The image runs from flash now, so trading ~20 KB for speed is free.
 */
#define HAVE_ED25519
#define HAVE_ED25519_SIGN
#define HAVE_ED25519_VERIFY
#define HAVE_ED25519_MAKE_KEY
#define HAVE_ED25519_KEY_IMPORT
#define HAVE_ED25519_KEY_EXPORT

/* ML-DSA / FIPS 204 (COSE -48/-49/-50), RFC 9964 seed-based keys.
 * SMALL_MEM keeps the working set down; wc_MlDsaKey is ~7.9 KB on its own and
 * cannot live on the 4 KB core-0 stack, so callers must keep it static.
 */
#define WOLFSSL_HAVE_MLDSA
#define WOLFSSL_MLDSA_SMALL_MEM
#define WOLFSSL_MLDSA_NO_ASN1
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256

/* SRAM PUF root of trust: the device master secret is reconstructed at boot
 * instead of being stored in flash. See src/puf_sram.c.
 *
 * BCH profile: t=13 (k=50) rather than the t=10 default. A reconstruction
 * failure here costs the user every registered credential, so error
 * correction is worth far more than footprint. Exact binomial tails for the
 * per-boot failure probability, 16 codewords of 127 bits:
 *
 *      SRAM BER    t=10      t=13      t=15
 *          3%      2.6e-2    4.9e-4    2.4e-5
 *          4%      1.9e-1    9.5e-3    8.2e-4
 *          5%      5.9e-1    7.2e-2    1.0e-2
 *          6%      9.1e-1    2.8e-1    6.2e-2
 *
 * The default t=10 fails well over half of all boots at 5% BER, which is
 * within the normal range for SRAM PUFs. t=13 is ~100x better there.
 *
 * t=15 is better still, but the code-offset construction leaks (n-k) bits per
 * codeword, so usable min-entropy is about ncw * (127*rho - (127-k)) for an
 * SRAM min-entropy rate rho. At 16 codewords:
 *
 *      rho     t=10      t=13      t=15
 *      0.70    414 bits  190 bits    0 bits
 *      0.75    516 bits  292 bits   68 bits
 *      0.80    618 bits  394 bits  170 bits
 *
 * t=15 collapses below the 128-bit security level of the P-256 credential
 * keys as soon as rho is pessimistic, and reaches zero at rho=0.70. t=13
 * stays above 128 bits across the whole plausible range. Raising the codeword
 * count would buy back entropy but costs reliability, since reconstruction
 * fails if any single codeword exceeds t.
 *
 * Enrollment and reconstruction must agree on these values or the derived key
 * is silently wrong; puf_sram.c persists WC_PUF_PROFILE_ID with the helper
 * data and checks it via wc_PufReconstructEx().
 */
#define WOLFSSL_PUF
#define WC_PUF_BCH_T          13
#define WC_PUF_NUM_CODEWORDS  16
extern int custom_random_seed(unsigned char* output, unsigned int sz);
#define CUSTOM_RAND_GENERATE_SEED custom_random_seed

//#define WOLFSSL_ASN_TEMPLATE

/* ECDSA. P-256 covers ES256 (-7) and the fully-specified ESP256 (-9);
 * P-384 covers ES384 (-35) / ESP384 (-51); P-521 covers ES512 (-36) /
 * ESP512 (-52). FP_MAX_BITS must reach twice the largest curve.
 */
#define HAVE_ECC
#   define ECC_TIMING_RESISTANT
#   define HAVE_ECC256
#   define HAVE_ECC384
#   define HAVE_ECC521
#   define FP_MAX_BITS (521 * 2 + 64)
#   define SP_WORD_SIZE 32
#   ifndef ULLONG_MAX
#       define ULLONG_MAX 18446744073709551615ULL
#   endif
#   define WOLFSSL_SP
#   define WOLFSSL_SP_MATH
#   define WOLFSSL_HAVE_SP_ECC
#   define WOLFSSL_SP_384
#   define WOLFSSL_SP_521

#define WOLFSSL_CURVE25519

#define NO_INLINE


/* SP math: WOLFSSL_SP_MATH selects the reduced implementation that only
 * covers the SP-accelerated curves (P-256 here). It is mutually exclusive
 * with WOLFSSL_SP_MATH_ALL, which wolfSSL enforces since v5.9.
 */
#define WOLFSSL_SP_SMALL
//#define WOLFSSL_SP_ARM_ARCH 4
#define WOLFSSL_SP_ARM_THUMB_ASM

/* Disables - For minimum wolfCrypt build */
/* Fidelio never derives keys from passwords; also drops the encrypted-key
 * paths in asn.c that pull in wc_CryptKey. */
#define NO_PWDBASED
#define NO_PKCS8
#define NO_PKCS12
#define NO_CMAC
#define NO_RSA
#define NO_RC4
#define NO_SHA
#define NO_DH
#define NO_DSA
#define NO_MD4
#define NO_RABBIT
#define NO_MD5
#define NO_CERT
#define NO_SESSION_CACHE
#define NO_HC128
#define NO_DES3
#define NO_WRITEV
#define NO_DEV_RANDOM
#define NO_FILESYSTEM
#define NO_MAIN_DRIVER
#define NO_OLD_RNGNAME
#define NO_WOLFSSL_DIR
#define WOLFSSL_NO_SOCK


/* SP temporaries go on the heap, not the stack: core 0's stack is pinned to
 * SCRATCH_Y's 4 KB by the SDK memory map, which P-521 and ML-DSA would
 * overflow. Running from flash leaves ~240 KB of RAM for the heap, so this
 * costs nothing. NO_DYN_STACK stays on to keep alloca out of the picture.
 */
#define WOLFSSL_SP_NO_DYN_STACK

#endif /* !H_USER_SETTINGS_ */
