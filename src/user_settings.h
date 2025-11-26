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


#define WOLFSSL_SP
#define WOLFSSL_SP_SMALL
#define WOLFSSL_SP_MATH
#define WOLFSSL_SP_MATH_ALL
//#define WOLFSSL_SP_ARM_ARCH 4
#define WOLFSSL_SP_ARM_THUMB_ASM
#define SP_WORD_SIZE 32
#define SINGLE_THREADED

/* Disables - For minimum wolfCrypt build */
#define NO_CMAC
#define NO_RSA
#define NO_BIG_INT
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
