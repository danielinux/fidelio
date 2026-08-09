/* Fidelio
 *
 * (c) 2023 Daniele Lacamera <root@danielinux.net>
 *
 * Fidelio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Fidelio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/* Build-sizing probe. Not part of the firmware.
 *
 * Measuring what an algorithm costs is meaningless until something calls it:
 * with --gc-sections the linker discards every entry point the image never
 * reaches, so simply enabling a wolfSSL feature macro reports a fraction of
 * the real footprint. This file references the signing paths Fidelio would
 * actually use, so a probe build reports the true cost of adding an
 * algorithm.
 *
 * Enable with -DFIDELIO_ALG_PROBE=ON. Never enable it for a real build.
 */

#ifdef FIDELIO_ALG_PROBE

#include <stdint.h>
#include <string.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/random.h"

#ifdef HAVE_ED25519
#include "wolfssl/wolfcrypt/ed25519.h"
#endif
#ifdef WOLFSSL_HAVE_MLDSA
#include "wolfssl/wolfcrypt/wc_mldsa.h"
#endif

static uint8_t probe_seed[32];
static uint8_t probe_msg[32];
static uint8_t probe_sig[5000];
static uint8_t probe_pub[3000];

void fidelio_alg_probe(void);

void fidelio_alg_probe(void)
{
#ifdef HAVE_ED25519
    {
        ed25519_key k;
        word32 sigLen = sizeof(probe_sig);
        word32 pubLen = sizeof(probe_pub);
        if (wc_ed25519_init(&k) == 0) {
            (void)wc_ed25519_import_private_only(probe_seed, 32, &k);
            (void)wc_ed25519_make_public(&k, probe_pub, pubLen);
            (void)wc_ed25519_export_public(&k, probe_pub, &pubLen);
            (void)wc_ed25519_sign_msg(probe_msg, sizeof(probe_msg),
                                      probe_sig, &sigLen, &k);
            wc_ed25519_free(&k);
        }
    }
#endif

#ifdef WOLFSSL_HAVE_MLDSA
    {
        wc_MlDsaKey k;
        WC_RNG rng;
        word32 sigLen = sizeof(probe_sig);
        word32 pubLen = sizeof(probe_pub);
        int level;
    #ifndef WOLFSSL_NO_ML_DSA_44
        level = WC_ML_DSA_44;
    #elif !defined(WOLFSSL_NO_ML_DSA_65)
        level = WC_ML_DSA_65;
    #else
        level = WC_ML_DSA_87;
    #endif
        if (wc_MlDsaKey_Init(&k, NULL, INVALID_DEVID) == 0) {
            (void)wc_MlDsaKey_SetParams(&k, (byte)level);
            (void)wc_MlDsaKey_MakeKeyFromSeed(&k, probe_seed);
            (void)wc_MlDsaKey_ExportPubRaw(&k, probe_pub, &pubLen);
            if (wc_InitRng(&rng) == 0) {
                /* FIPS 204 signing with an empty context, which is what
                 * COSE/WebAuthn uses. */
                (void)wc_MlDsaKey_SignCtx(&k, NULL, 0, probe_sig, &sigLen,
                                          probe_msg, sizeof(probe_msg), &rng);
                wc_FreeRng(&rng);
            }
            wc_MlDsaKey_Free(&k);
        }
    }
#endif
}

#endif /* FIDELIO_ALG_PROBE */
