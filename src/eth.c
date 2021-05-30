#include <sys/random.h>
#include <secp256k1.h>
#include <ethash/keccak.h>

#include <assert.h>
#include <string.h>
#include <ctype.h>

#include <aether/eth.h>
#include <aether/util.h>

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

void aether_secp256k1_calcpkey(aether_secp256k1_unc_pubkey* pk, const secp256k1_context* ctx, const aether_secp256k1_seckey* sk) {
    //Generate public key
    secp256k1_pubkey secp_pubkey;
    int pkcres = secp256k1_ec_pubkey_create(ctx, &secp_pubkey, sk->data);
    assert(pkcres);

    //Write secp256k1 public key to uncompressed 65-bit representation
    size_t outputlen = 65;
    secp256k1_ec_pubkey_serialize(ctx, pk->data, &outputlen, &secp_pubkey, SECP256K1_EC_UNCOMPRESSED);
}

void aether_keccak256_bhash(aether_keccak256_hash* kh, const unsigned char* data) {
    union ethash_hash256 ehash = ethash_keccak256(data, 64);
    memcpy(kh->data, ehash.str, 32);
}

void aether_keccak256_pkhash(aether_eth_pubkey_khash* kh, const aether_secp256k1_unc_pubkey* pk) {
    //Grab the pointer up from the public key, as we ignore the first uncompressed byte
    const unsigned char* pk_data = pk->data + 1;
    aether_keccak256_bhash(kh, pk_data);
}

const unsigned char* aether_eth_pubkey_khash_getaddress(const aether_eth_pubkey_khash* kh) {
    return kh->data+12;
}

void aether_eth_pubkey_khash_writeeip55address(FILE* stream, const aether_eth_pubkey_khash* kh) {
    char loweraddr[41];
    aether_util_bytestohexstring(loweraddr, aether_eth_pubkey_khash_getaddress(kh), 20);
    aether_util_tolowerstr(loweraddr);    

    //Hash the lowercase address
    union ethash_hash256 ehash = ethash_keccak256((unsigned char*) loweraddr, 40);
    char ehash_digits[41];
    aether_util_bytestohexstring(ehash_digits, (unsigned char*) ehash.str, 20);

    //Finally, using the hash, write each char according to EIP-55, checking if
    //the character hex value of the hash is greater than 8
    for(int i = 0; i < 40; ++i) {
        if(isalpha(loweraddr[i]) && (aether_util_hexchartoi(ehash_digits[i]) >= 0x8)) {
            putc(toupper(loweraddr[i]), stream);
        } else {
            putc(loweraddr[i], stream);
        }
    }
}

void aether_eth_pubkey_khash_eip55addresstostring(char* out, const aether_eth_pubkey_khash* kh) {
    aether_util_bytestohexstring(out, aether_eth_pubkey_khash_getaddress(kh), 20);
    aether_util_tolowerstr(out);

    //Hash the lowercase address
    union ethash_hash256 ehash = ethash_keccak256((unsigned char*) out, 40);

    //Finally, using the hash, write each char according to EIP-55, checking if
    //the character hex value of the hash is greater than 8
    for(int i = 0; i < 40; ++i) {
        if(isalpha(out[i]) && (aether_util_hexchartoi(ehash.str[i]) >= 0x8)) {
            out[i] = toupper(out[i]);
        }
    }
}

int aether_eth_address_iszero(aether_eth_address* addr) {
    for(size_t i = 0; i < 20; ++i) {
        if(addr->data[i] != 0) {
            return 0;
        }
    }
    return 1;
}
