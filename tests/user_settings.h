#ifndef HOST_USER_SETTINGS_H
#define HOST_USER_SETTINGS_H

#define SINGLE_THREADED
#define WOLFCRYPT_ONLY
#define HAVE_SHA256
#define HAVE_HASHDRBG
extern int host_random_seed(unsigned char* output, unsigned int sz);
#define CUSTOM_RAND_GENERATE_SEED host_random_seed
#define HAVE_HKDF

#define HAVE_ECC
#define ECC_TIMING_RESISTANT
#define HAVE_ECC256
#define FP_MAX_BITS (256 + 256)
#define WOLFSSL_SP
#define WOLFSSL_SP_MATH
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_SMALL
#define SP_WORD_SIZE 32
#define WOLFSSL_SP_NO_MALLOC
#define WOLFSSL_SP_NO_DYN_STACK

#define NO_CMAC
#define NO_RSA
#define NO_RC4
#define NO_SHA
#define NO_DH
#define NO_DSA
#define NO_MD4
#define NO_MD5
#define NO_DES3
#define NO_SESSION_CACHE
#define NO_WRITEV
#define NO_FILESYSTEM
#define NO_MAIN_DRIVER
#define NO_OLD_RNGNAME
#define NO_WOLFSSL_DIR
#define WOLFSSL_NO_SOCK

#endif
