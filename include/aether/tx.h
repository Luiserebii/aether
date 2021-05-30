#ifndef AETHER_TX_H
#define AETHER_TX_H

#ifdef __cplusplus
extern "C" {
#endif

#include <aether/eth.h>
#include <aether/vector-uchar.h>

struct aether_eth_tx_sig {
    unsigned long long v;
    unsigned long long r;
    unsigned long long s;
};

/**
 * TODO: These scalar fields should be either mpz_t or unsigned char[32] (256-bit)
 */
struct aether_eth_tx {
    unsigned long long nonce;
    unsigned long long gasprice;
    unsigned long long gaslimit;
    aether_eth_address to;
    unsigned long long value;
    struct { //alternatively, init
        unsigned char* bytes;
        size_t sz;
    } data;
    unsigned long long v;
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
