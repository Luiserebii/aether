#include <assert.h>
#include <string.h>
#include <ctype.h>

#include <secp256k1.h>
#include <ethash/keccak.h>

#include <aether/eth.h>
#include <aether-internal/util.h>

void aether_eth_pkhash_from_pk(aether_eth_pkhash* kh, const aether_secp256k1_unc_pubkey* pk) {
    //Grab the pointer up from the public key, as we ignore the first uncompressed byte
    const unsigned char* pk_data = pk->data + 1;
    aether_keccak256_bhash(kh, pk_data, 64);
}

const unsigned char* aether_eth_pkhash_getaddress(const aether_eth_pkhash* kh) {
    return kh->data+12;
}

void aether_eth_pkhash_writeeip55address(FILE* stream, const aether_eth_pkhash* kh) {
    char loweraddr[41];
    aether_util_bytestohexstring(loweraddr, aether_eth_pkhash_getaddress(kh), 20);
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

void aether_eth_pkhash_eip55addresstostring(char* out, const aether_eth_pkhash* kh) {
    aether_util_bytestohexstring(out, aether_eth_pkhash_getaddress(kh), 20);
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

int aether_eth_address_iszero(const aether_eth_address* addr) {
    return aether_util_uchar_arr_iszero(addr->data, addr->data + 20);
}
