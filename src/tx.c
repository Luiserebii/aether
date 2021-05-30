#include <aether/tx.h>
#include <aether/vector-uchar.h>
#include <aether/eth.h>
#include <aether/rlp.h>
#include <aether/util.h>

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

    aether_rlp_t_encode(&tx_rlp, tx_sig);
}

void aether_secp256k1_ecdsa_sign(struct aether_eth_tx_sig* sig, const aether_secp256k1_seckey* sk, const unsigned char* data, const secp256k1_context* ctx) {
    //Generation of ephemeral private and public keys
    aether_secp256k1_seckey eph_sk;
    aether_secp256k1_genskey(&eph_sk, ctx);

    aether_secp256k1_unc_pubkey eph_pk;
    aether_secp256k1_calcpkey(&eph_pk, ctx, &eph_sk);
    
    //Set up values for modular arithmetic
    mpz_t q, r, k, z, p, s;
    mpz_inits(q, r, k, z, p, s, NULL);
    aether_util_mpz_import(q, 32, eph_sk.data);
    aether_util_mpz_import(r, 32, eph_pk.data + 1);
    aether_util_mpz_import(k, 32, sk->data);
    aether_util_mpz_import(z, 32, data);
    mpz_set_str(p, "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);

    //Release mpz_t values
    mpz_clears(q, r, k, z, p, s, NULL);
}
