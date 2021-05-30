#ifndef AETHER_TX_H
#define AETHER_TX_H

#ifdef __cplusplus
extern "C" {
#endif

#include <aether/eth.h>
#include <aether/vector-uchar.h>

struct aether_eth_tx_sig {
    unsigned char v[32];
    unsigned char r[32];
    unsigned char s[32];
};

/**
 * TODO: These scalar fields should be either mpz_t or unsigned char[32] (256-bit)
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

void aether_eth_tx_sign(const struct aether_eth_tx* tx, const aether_secp256k1_seckey* sk, vector_uchar* tx_sig, const secp256k1_context* ctx);

/**
 * Should const unsigned char* data be 32-byte?
 */
void aether_secp256k1_ecdsa_sign(struct aether_eth_tx_sig* sig, const aether_secp256k1_seckey* sk, const unsigned char* data, const secp256k1_context* ctx);

#ifdef __cplusplus
}
#endif

#endif
