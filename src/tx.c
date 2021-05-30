#include <aether/tx.h>
#include <aether/vector-uchar.h>
#include <aether/eth.h>
#include <aether/rlp.h>

#include <gmp.h>
#include <secp256k1.h>



void aether_eth_tx_sign(const struct aether_eth_tx* tx, const aether_secp256k1_seckey* sk, vector_uchar* tx_sig, const secp256k1_context* ctx) {
    //Encode transaction as RLP-serialized
    struct aether_rlp_t tx_rlp;
    aether_rlp_t_init_tx(&tx_rlp, tx);
    aether_rlp_t_encode(&tx_rlp, tx_sig);

    //Keccak256 hash of RLP-serialized data
    aether_keccak256_hash tx_hash;
    aether_keccak256_bhash(&tx_hash, vector_uchar_begin(tx_sig), vector_uchar_size(tx_sig));

    //Sign our hash using our private key, obtaining our v, r, s values
    struct aether_eth_tx_sig sig;
    aether_secp256k1_ecdsa_sign(&sig, sk, tx_hash.data, ctx);

    //Finally, add v, r, s and re-encode
    vector_uchar_clear(tx_sig);
    struct aether_rlp_t* e = vector_rlp_t_begin(&tx_rlp.value.list) + 6;
    aether_rlp_t_set_byte_array_scalarull(e++, sig.v);
    aether_rlp_t_set_byte_array_scalarull(e++, sig.r);
    aether_rlp_t_set_byte_array_scalarull(e, sig.s);
}

void aether_secp256k1_ecdsa_sign(struct aether_eth_tx_sig* sig, const aether_secp256k1_seckey* sk, const unsigned char* data, const secp256k1_context* ctx) {
    
    

}
