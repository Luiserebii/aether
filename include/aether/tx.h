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

struct aether_secp256k1_ecdsa_sig {
    unsigned char rs[64];
    int r_id;
};

void aether_eth_tx_sign(const struct aether_eth_tx* tx, const aether_secp256k1_seckey* sk, struct aether_vector_uchar* tx_sig, const secp256k1_context* ctx);

void aether_secp256k1_ecdsa_sign_alt(struct aether_secp256k1_ecdsa_sig* sig, const aether_secp256k1_seckey* sk, const unsigned char* data, const secp256k1_context* ctx);

/**
 * Calculate the numerical value {0, 1} using the parity of the y-coordinate.
 * pk_y is assumed to be of 32 bytes in size.
 */
int aether_secp256k1_pk_y_parity(const unsigned char* pk_y);

void aether_secp256k1_ecdsa_calc_v_alt(unsigned char* v, int recoveryid, const unsigned char* chainid);
  
/**
 * Calculate v, as chainid * 2 + 35 + parity of pk_y (i.e. {0, 1}).
 * v, pk_y, and chainid are all assumed to be of 32 bytes in size.
 */
void aether_secp256k1_ecdsa_calc_v(unsigned char* v, const unsigned char* pk_y, const unsigned char* chainid);

/**
 */
void aether_secp256k1_ecdsa_sign(struct aether_eth_tx_sig* sig, const aether_secp256k1_seckey* sk, const unsigned char* data, const unsigned char* chainid, const secp256k1_context* ctx);

#ifdef __cplusplus
}
#endif

#endif
