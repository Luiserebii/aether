#ifndef AETHER_TX_H
#define AETHER_TX_H

#ifdef __cplusplus
extern "C" {
#endif

#include <aether/eth.h>
#include <aether/vector/vector-uchar.h>

struct aether_eth_tx_sig {
    unsigned char v[32];
    unsigned char r[32];
    unsigned char s[32];
};

/**
 * The Ethereum transaction data representation. The `data` field is synonymous
 * with `init` when used for contract creation, serving the same purpose and
 * location in encoding.
 */
struct aether_eth_tx {
    unsigned char nonce[32];
    unsigned char gasprice[32];
    unsigned char gaslimit[32];
    aether_eth_address to;
    unsigned char value[32];
    struct { //alternatively, init
        unsigned char* bytes;
        size_t sz;
    } data;
    struct aether_eth_tx_sig sig;
};

/**
 * Initializes an aether_eth_tx using the fields specified as null-terminated strings, where:
 *    * n, gp, gl, val, cid are decimal scalar values
 *    * addr, d are hexadecimal scalar values (with no "0x" prefix)
 *
 * Note that although this function allocates memory for data->bytes, and thus aether_eth_tx_deinit
 * must be called in order to release the proper resources, it is not necessary to use this 
 * initialization function to bring the struct to a valid state. Simply ensuring that the fields
 * contain valid accessible data is fine enough. This function is really only useful when naively
 * redirecting string input into a transaction; when values are being calculated, such as the nonce,
 * it is more useful to write a function to write into aether_eth_tx directly, to avoid unneeded
 * conversions.
 */
void aether_eth_tx_init(struct aether_eth_tx* tx, const char* n, const char* gp, const char* gl, const char* addr, const char* val, const char* d, const char* cid);

/**
 * Signs an aether_eth_tx by providing the v, r, s values in tx_sig, using EIP-155. Please note that
 * tx->sig.v is required to contain the chain ID before calling.
 */
void aether_eth_tx_sign(struct aether_vector_uchar* tx_sig, const struct aether_eth_tx* tx, const aether_secp256k1_seckey* sk, const secp256k1_context* ctx);

/**
 * Calculates a valid v using the recovery id (a value {0, 1} representing the parity
 * of the y-coordinate of the ephemeral public key) and a chain ID.
 */
void aether_eth_tx_calc_v(unsigned char* v, int recoveryid, const unsigned char* chainid);

/**
 * Deinitializes an aether_eth_tx by releasing memory allocated by aether_eth_tx_init.
 */
void aether_eth_tx_deinit(struct aether_eth_tx* tx);

/*********************************************************************************************************
 * Alternative implementations; would be neat to get this working in the future, although unneeded
 */

/**
 * Calculate the numerical value {0, 1} using the parity of the y-coordinate.
 * pk_y is assumed to be of 32 bytes in size.
 */
int aether_secp256k1_pk_y_parity_alt(const unsigned char* pk_y);
  
/**
 * Calculate v, as chainid * 2 + 35 + parity of pk_y (i.e. {0, 1}).
 * v, pk_y, and chainid are all assumed to be of 32 bytes in size.
 */
void aether_secp256k1_ecdsa_calc_v_alt(unsigned char* v, const unsigned char* pk_y, const unsigned char* chainid);

/**
 */
void aether_secp256k1_ecdsa_sign_alt(struct aether_eth_tx_sig* sig, const aether_secp256k1_seckey* sk, const unsigned char* data, const unsigned char* chainid, const secp256k1_context* ctx);

#ifdef __cplusplus
}
#endif

#endif
