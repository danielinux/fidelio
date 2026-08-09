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
#define HAVE_HASHDRBG
#define HAVE_HKDF

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

#define HAVE_ECC
#   define ECC_TIMING_RESISTANT
//#   define ECC_USER_CURVES /* enables only 256-bit by default */
/* ECC options disabled to reduce size */
#   define HAVE_ECC256
#   define FP_MAX_BITS (256 + 256)
#   define SP_WORD_SIZE 32
#   ifndef ULLONG_MAX
#       define ULLONG_MAX 18446744073709551615ULL
#   endif
#   define WOLFSSL_SP
#   define WOLFSSL_SP_MATH
#   define WOLFSSL_HAVE_SP_ECC

#define ED25519_SMALL
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


#define WOLFSSL_SP_NO_MALLOC
#define WOLFSSL_SP_NO_DYN_STACK

#endif /* !H_USER_SETTINGS_ */
