#ifndef AETHER_SECP256K1_H
#define AETHER_SECP256K1_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <secp256k1.h>

/**
 * secp256k1 secret key data type.
 */
typedef struct {
    unsigned char data[32];
} aether_secp256k1_seckey;

/**
 * secp256k1 uncompressed public key data type.
 */
typedef struct {
    unsigned char data[65];
} aether_secp256k1_unc_pubkey;

/**
 * secp256k1 ECDSA signature data type.
 */
struct aether_secp256k1_ecdsa_sig {
    unsigned char rs[64];
    int r_id;
};

/**
 * Generates a random secp256k1 secret key. Each byte is guaranteed to be in
 * the range of [0, 2^8-1]. Therefore, the value of the secret key is
 * guaranteed to be in the range of [0, 2^32-1].
 *
 * Note that this does not guarantee a *valid* random secp256k1 key.
 * See aether_secp256k1_genskey.
 */
const unsigned char* aether_secp256k1_randskey(aether_secp256k1_seckey* sk);

/**
 * Generates a random valid secp256k1 secret key. The value of the secret key
 * is guaranteed to be in the valid range, which is [1, order n of G].
 */
void aether_secp256k1_genskey(aether_secp256k1_seckey* sk, const secp256k1_context* ctx);

/**
 * Calculates the uncompressed secp256k1 public key from a secret key.
 * A secp256k1_context pointer is required.
 */
void aether_secp256k1_ecdsa_pubkey(aether_secp256k1_unc_pubkey* pk, const secp256k1_context* ctx, const aether_secp256k1_seckey* sk);

/**
 * Signs the 32-byte data32 argument with the secret key passed, 
 * storing the signature in sig.
 */
void aether_secp256k1_ecdsa_sign(struct aether_secp256k1_ecdsa_sig* sig, const aether_secp256k1_seckey* sk, const unsigned char* data32, const secp256k1_context* ctx);

/**
 * Recovers the public key using the data32 signed by sig, as well
 * as the signature through sig, returned in pk.
 */
int aether_secp256k1_ecdsa_recover(aether_secp256k1_unc_pubkey* pk, const struct aether_secp256k1_ecdsa_sig* sig, const unsigned char* data32, const secp256k1_context* ctx);

#ifdef __cplusplus
}
#endif

#endif
