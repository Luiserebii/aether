#ifndef AETHER_ETH_H
#define AETHER_ETH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <aether/secp256k1.h>
#include <aether/keccak256.h>

/**
 * Ethereum keccak256 hash of public key data type. 
 *
 * As this is a special kind of a keccak256 hash, it is typedef'd to express 
 * the unique functions this data type has (e.g. getting address)
 */
typedef aether_keccak256_hash aether_eth_pkhash;

/**
 * Ethereum address data type.
 */
typedef struct {
    unsigned char data[20];
} aether_eth_address;

/**
 * Calculates the keccak256 hash from a public key. 
 **/
void aether_eth_pkhash_from_pk(aether_eth_pkhash* kh, const aether_secp256k1_unc_pubkey* pk);

/**
 * Returns a pointer to the 20-byte segment containing a valid Ethereum address
 * from public key keccak256 hash.
 */
const unsigned char* aether_eth_pkhash_getaddress(const aether_eth_pkhash* kh);

/**
 * Writes 40 characters to the stream, the EIP-55 encoded address of the public key.
 */
void aether_eth_pkhash_writeeip55address(FILE* stream, const aether_eth_pkhash* kh);

/**
 * Writes 41 characters to out, the EIP-55 encoded address of the public key and a
 * null terminator. Note that this function could very well overrun out: **PLEASE**
 * ensure that the out buffer can store them.
 */
void aether_eth_pkhash_eip55addresstostring(char* out, const aether_eth_pkhash* kh);

/**
 * Returns non-zero if the address is empty.
 */
int aether_eth_address_iszero(const aether_eth_address* addr);

#ifdef __cplusplus
}
#endif

#endif
