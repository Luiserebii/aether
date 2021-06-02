#include <aether/tx.h>
#include <aether/eth.h>
#include <aether/rlp.h>
#include <aether/vector/vector-uchar.h>
#include <aether/secp256k1.h>

#include <aether-internal/util.h>

#include <string.h>

#include <gmp.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>

void aether_eth_tx_sign(struct aether_vector_uchar* tx_sig, const struct aether_eth_tx* tx, const aether_secp256k1_seckey* sk, const secp256k1_context* ctx) {
    //Encode transaction as RLP-serialized
    struct aether_rlp_t tx_rlp;
    aether_rlp_t_init_tx(&tx_rlp, tx);
    aether_rlp_t_encode(&tx_rlp, tx_sig);
    
    //Keccak256 hash of RLP-serialized data
    aether_keccak256_hash tx_hash;
    aether_keccak256_bhash(&tx_hash, aether_vector_uchar_begin(tx_sig), aether_vector_uchar_size(tx_sig));

    //Sign our hash using our private key, obtaining our v, r, s values
    struct aether_secp256k1_ecdsa_sig sig;
    aether_secp256k1_ecdsa_sign(&sig, sk, tx_hash.data, ctx);
    unsigned char v[32];
    aether_eth_tx_calc_v(v, sig.r_id, tx->sig.v);

    //Finally, add v, r, s and re-encode
    aether_vector_uchar_clear(tx_sig);
    struct aether_rlp_t* e = aether_vector_rlp_t_begin(&tx_rlp.value.list) + 6;
    aether_rlp_t_set_byte_array_scalarbytes(e++, v, v + 32);
    aether_rlp_t_set_byte_array_scalarbytes(e++, sig.rs, sig.rs + 32);
    aether_rlp_t_set_byte_array_scalarbytes(e, sig.rs + 32, sig.rs + 64);
    
    aether_rlp_t_encode(&tx_rlp, tx_sig);
    aether_rlp_t_deinit(&tx_rlp);
}


void aether_eth_tx_calc_v(unsigned char* v, int recoveryid, const unsigned char* chainid) {
    mpz_t v_num;
    mpz_init(v_num);
    aether_util_mpz_import(v_num, 32, chainid);
    mpz_mul_ui(v_num, v_num, 2);
    mpz_add_ui(v_num, v_num, 35 + recoveryid);
    aether_util_mpz_export(v, 32, v_num);
    mpz_clear(v_num);
}

void aether_secp256k1_ecdsa_sign(struct aether_secp256k1_ecdsa_sig* sig, const aether_secp256k1_seckey* sk, const unsigned char* data32, const secp256k1_context* ctx) {
    secp256k1_ecdsa_recoverable_signature r_sig;
    secp256k1_nonce_function nfn = secp256k1_nonce_function_rfc6979;
    secp256k1_ecdsa_sign_recoverable(ctx, &r_sig, data32, sk->data, nfn, NULL);

    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig->rs, &sig->r_id, &r_sig);
}

int aether_secp256k1_ecdsa_recover(aether_secp256k1_unc_pubkey* pk, const struct aether_secp256k1_ecdsa_sig* sig, const unsigned char* data32, const secp256k1_context* ctx) {
    secp256k1_pubkey s_pk;
    secp256k1_ecdsa_recoverable_signature s_sig;
    secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &s_sig, sig->rs, sig->r_id);

    int res = secp256k1_ecdsa_recover(ctx, &s_pk, &s_sig, data32);
    if(!res) {
        return 0;
    } 
    size_t sz = 65;
    secp256k1_ec_pubkey_serialize(ctx, pk->data, &sz, &s_pk, SECP256K1_EC_UNCOMPRESSED); 
    return 1;
}

/**
 * Alternative implementations; would be neat to get this working in the future, although unneeded
 */

int aether_secp256k1_pk_y_parity(const unsigned char* pk_y) {
    return aether_util_hexchartouchar(pk_y[31]) % 2 == 0 ? 0 : 1;
}

void aether_secp256k1_ecdsa_calc_v_alt(unsigned char* v, const unsigned char* pk_y, const unsigned char* chainid) {
    mpz_t v_num;
    mpz_init(v_num);
    aether_util_mpz_import(v_num, 32, chainid);
    mpz_mul_ui(v_num, v_num, 2);
    mpz_add_ui(v_num, v_num, 35 + aether_secp256k1_pk_y_parity(pk_y));
    aether_util_mpz_export(v, 32, v_num);
    mpz_clear(v_num);
}

void aether_secp256k1_ecdsa_sign_alt(struct aether_eth_tx_sig* sig, const aether_secp256k1_seckey* sk, const unsigned char* data, const unsigned char* chainid, const secp256k1_context* ctx) {
    //Generation of ephemeral private and public keys
    aether_secp256k1_seckey eph_sk;
    aether_secp256k1_genskey(&eph_sk, ctx);

    aether_secp256k1_unc_pubkey eph_pk;
    aether_secp256k1_calcpkey(&eph_pk, ctx, &eph_sk);
    
    //Set up values for modular arithmetic
    mpz_t q, r, k, z, p, s, val;
    mpz_inits(q, r, k, z, p, s, val, NULL);
    aether_util_mpz_import(q, 32, eph_sk.data);
    aether_util_mpz_import(r, 32, eph_pk.data + 1);
    aether_util_mpz_import(k, 32, sk->data);
    aether_util_mpz_import(z, 32, data);
    mpz_set_str(p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);

    //Perform modular arithmetic to calculate s
    //Using ECDSA paper suggests line below
    //mpz_mod(r, r, p);
    mpz_mul(val, r, k);
    mpz_add(val, z, val);
    mpz_invert(q, q, p);
    mpz_mul(val, val, q);
    mpz_mod(s, val, p);

    //Set v, r, (and s?)
    aether_secp256k1_ecdsa_calc_v_alt(sig->v, eph_pk.data + 32 + 1, chainid);
    memcpy(sig->r, eph_pk.data + 1, 32);
    aether_util_mpz_export(sig->s, 32, s);

    //Release mpz_t values
    mpz_clears(q, r, k, z, p, s, val, NULL);
}
