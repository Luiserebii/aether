#ifndef MINTH_ETH_H
#define MINTH_ETH_H

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
} eth_secp256k1_seckey;

/**
 * secp256k1 uncompressed public key data type.
 */
typedef struct {
    unsigned char data[65];
} eth_secp256k1_unc_pubkey;

/**
 * secp256k1 keccak256 hash data type.
 */
typedef struct {
    unsigned char data[32];
} eth_keccak256_hash;

/**
 * Ethereum keccak256 hash of public key data type. 
 *
 * As this is a special kind of a keccak256 hash, it is typedef'd to express 
 * the unique functions this data type has (e.g. getting address)
 */
typedef eth_keccak256_hash eth_pubkey_khash;

/**
 * Generates a random secp256k1 secret key. Each byte is guaranteed to be in
 * the range of [0, 2^8-1]. Therefore, the value of the secret key is
 * guaranteed to be in the range of [0, 2^32-1].
 *
 * Note that this does not guarantee a *valid* random secp256k1 key.
 * See eth_secp256k1_generateseckey.
 */
unsigned char* eth_secp256k1_randseckey(eth_secp256k1_seckey* sk);

/**
 * Generates a random valid secp256k1 secret key. The value of the secret key
 * is guaranteed to be in the valid range, which is [1, order n of G].
 */
void eth_secp256k1_generateseckey(eth_secp256k1_seckey* sk, const secp256k1_context* ctx);

/**
 * Calculates the uncompressed secp256k1 public key from a secret key.
 * A secp256k1_context pointer is required.
 */
void eth_secp256k1_calculatepubkey(eth_secp256k1_unc_pubkey* pk, const secp256k1_context* ctx, const eth_secp256k1_seckey* sk);

/**
 * Calculates the keccak256 hash from any arbitrary data.
 */
void eth_keccak_calculatepkhash(eth_keccak256_hash* kh, const unsigned char* data);

/**
 * Calculates the keccak256 hash from a public key. 
 **/
void eth_pubkey_khash_calculate(eth_pubkey_khash* kh, const eth_secp256k1_unc_pubkey* pk);

/**
 * Returns a pointer to the 20-byte segment containing a valid Ethereum address
 * from public key keccak256 hash.
 */
const unsigned char* eth_pubkey_khash_getaddress(const eth_pubkey_khash* kh);

/**
 * Writes 40 characters to the stream, the EIP-55 encoded address of the public key.
 */
void eth_pubkey_khash_writeeip55address(FILE* stream, const eth_pubkey_khash* kh);

/**
 * Writes 41 characters to out, the EIP-55 encoded address of the public key and a
 * null terminator. Note that this function could very well overrun out: **PLEASE**
 * ensure that the out buffer can store them.
 */
void eth_pubkey_khash_eip55addresstostring(char* out, const eth_pubkey_khash* kh);

/**
 * Writes the hex string along [b, e) to the byte array at bytes. Every two characters
 * are stored into a single element of the byte array. This function could very well
 * overrun the bytes buffer: **PLEASE** ensure that (e-b)/2 < the size of bytes.
 *
 * The unsigned char* bytes is required to be zero-initialized, otherwise the call
 * to this function will cause a bad write.
 **/
void minth_util_hexstringtobytes(unsigned char* bytes, const char* b, const char* e);

/**
 * Writes bytes_sz * 2 + 1 characters to the char string located by out.
 * Note that this function will only write the 8-bit value of each byte,
 * ignoring any other values (therefore any char larger than 8-bits will
 * have those ignored).
 *
 * The one off the end of the string is returned. If out at the start of the
 * function were a, and out at the end were b, then the range of the written
 * string would thus be [a, b).
 *
 * Note that this function could very well overwrite the out buffer: **PLEASE**
 * ensure that out can store bytes_z * 2 + 1 characters.
 */
char* eth_util_bytestohexstring(char* out, const unsigned char* bytes, size_t bytes_sz);

/**
 * Writes bytes_sz * 2 + 1 characters to the FILE* located by stream.
 * Note that this function will only write the 8-bit value of each byte,
 * ignoring any other values (therefore any char larger than 8-bits will
 * have those ignored).
 */
void eth_util_writebytestohex(FILE* stream, const unsigned char* bytes, size_t bytes_sz);

#ifdef __cplusplus
}
#endif

#endif
