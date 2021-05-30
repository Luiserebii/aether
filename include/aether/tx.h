#ifndef AETHER_TX_H
#define AETHER_TX_H

#ifdef __cplusplus
extern "C" {
#endif

#include <aether/eth.h>

struct aether_eth_tx_sig {
    unsigned long long v;
    unsigned long long r;
    unsigned long long s;
};

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

#ifdef __cplusplus
}
#endif

#endif
