#include <aether/tx.h>
#include <aether/vector-uchar.h>
#include <aether/eth.h>
#include <aether/rlp.h>

#include <gmp.h>
#include <secp256k1.h>



void aether_eth_tx_sign(const struct aether_eth_tx* tx, const aether_secp256k1_seckey* sk, vector_uchar* tx_sig) {
    struct aether_rlp_t tx_rlp;
    aether_rlp_t_init_tx(&tx_rlp, tx);

}

void aether_secp256k1_ecdsa_sign(struct aether_eth_tx_sig* sig, const aether_secp256k1_seckey* sk, const secp256k1_context* ctx) {

    

}
