#ifndef AETHER_ETH_H
#define AETHER_ETH_H

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
 * secp256k1 keccak256 hash data type.
 */
typedef struct {
    unsigned char data[32];
} aether_keccak256_hash;

/**
 * Ethereum keccak256 hash of public key data type. 
 *
 * As this is a special kind of a keccak256 hash, it is typedef'd to express 
 * the unique functions this data type has (e.g. getting address)
 */
typedef aether_keccak256_hash aether_eth_pubkey_khash;

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
void aether_secp256k1_calcpkey(aether_secp256k1_unc_pubkey* pk, const secp256k1_context* ctx, const aether_secp256k1_seckey* sk);

/**
 * Calculates the keccak256 hash from any arbitrary data.
 */
void aether_keccak256_bhash(aether_keccak256_hash* kh, const unsigned char* data);

/**
 * Calculates the keccak256 hash from a public key. 
 **/
void aether_keccak256_pkhash(aether_eth_pubkey_khash* kh, const aether_secp256k1_unc_pubkey* pk);

/**
 * Returns a pointer to the 20-byte segment containing a valid Ethereum address
 * from public key keccak256 hash.
 */
const unsigned char* aether_eth_pubkey_khash_getaddress(const aether_eth_pubkey_khash* kh);

/**
 * Writes 40 characters to the stream, the EIP-55 encoded address of the public key.
 */
void aether_eth_pubkey_khash_writeeip55address(FILE* stream, const aether_eth_pubkey_khash* kh);

/**
 * Writes 41 characters to out, the EIP-55 encoded address of the public key and a
 * null terminator. Note that this function could very well overrun out: **PLEASE**
 * ensure that the out buffer can store them.
 */
void aether_eth_pubkey_khash_eip55addresstostring(char* out, const aether_eth_pubkey_khash* kh);

#ifdef __cplusplus
}
#endif

#endif
