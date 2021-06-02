#include <assert.h>
#include <string.h>
#include <sys/random.h>

#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include <aether/secp256k1.h>
#include <aether-internal/util.h>

void aether_secp256k1_seckey_import(aether_secp256k1_seckey* sk, const char* s) {
    memset(sk->data, 0, 32);
    aether_util_hexstringtobytes(sk->data, s, s + strlen(s));
}

const unsigned char* aether_secp256k1_randskey(aether_secp256k1_seckey* sk) {
    //Fill our raw buffer with CSPRNG bytes from /dev/urandom
    getrandom(sk->data, 32, 0);
    //Mask off all unneeded bytes
    for(size_t i = 0; i < 32; ++i) {
        sk->data[i] &= 0xFF;
    }
    return sk->data;
}

void aether_secp256k1_genskey(aether_secp256k1_seckey* sk, const secp256k1_context* ctx) {
    //Generate a new one until valid
    while(!secp256k1_ec_seckey_verify(ctx, aether_secp256k1_randskey(sk)))
        ;
}

void aether_secp256k1_ecdsa_pubkey(aether_secp256k1_unc_pubkey* pk, const secp256k1_context* ctx, const aether_secp256k1_seckey* sk) {
    //Generate public key
    secp256k1_pubkey secp_pubkey;
    int pkcres = secp256k1_ec_pubkey_create(ctx, &secp_pubkey, sk->data);
    assert(pkcres);

    //Write secp256k1 public key to uncompressed 65-bit representation
    size_t outputlen = 65;
    secp256k1_ec_pubkey_serialize(ctx, pk->data, &outputlen, &secp_pubkey, SECP256K1_EC_UNCOMPRESSED);
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

