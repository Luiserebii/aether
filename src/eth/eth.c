#include <sys/random.h>
#include <secp256k1.h>
#include <ethash/keccak.h>

#include <assert.h>
#include <string.h>
#include <ctype.h>

#include "../../include/eth/eth.h"

/**
 * Changes all characters in str to lowercase.
 **/
static void minth_util_tolowerstr(char* str) {
    while((*str = tolower(*str)) && ++str)
        ;
}

unsigned char* eth_secp256k1_randseckey(eth_secp256k1_seckey* sk) {
    //Fill our raw buffer with CSPRNG bytes from /dev/urandom
    getrandom(sk->data, 32, 0);
    //Mask off all unneeded bytes
    for(size_t i = 0; i < 32; ++i) {
        sk->data[i] &= 0xFF;
    }
    return sk->data;
}

void eth_secp256k1_generateseckey(eth_secp256k1_seckey* sk, const secp256k1_context* ctx) {
    //Generate a new one until valid
    while(!secp256k1_ec_seckey_verify(ctx, eth_secp256k1_randseckey(sk)))
        ;
}

void eth_secp256k1_calculatepubkey(eth_secp256k1_unc_pubkey* pk, const secp256k1_context* ctx, const eth_secp256k1_seckey* sk) {
    //Generate public key
    secp256k1_pubkey secp_pubkey;
    int pkcres = secp256k1_ec_pubkey_create(ctx, &secp_pubkey, sk->data);
    assert(pkcres);

    //Write secp256k1 public key to uncompressed 65-bit representation
    size_t outputlen = 65;
    secp256k1_ec_pubkey_serialize(ctx, pk->data, &outputlen, &secp_pubkey, SECP256K1_EC_UNCOMPRESSED);
}

void eth_keccak_calculatepkhash(eth_keccak256_hash* kh, const unsigned char* data) {
    union ethash_hash256 ehash = ethash_keccak256(data, 64);
    memcpy(kh->data, ehash.str, 32);
}

void eth_pubkey_khash_calculate(eth_pubkey_khash* kh, const eth_secp256k1_unc_pubkey* pk) {
    //Grab the pointer up from the public key, as we ignore the first uncompressed byte
    const unsigned char* pk_data = pk->data + 1;
    eth_keccak_calculatepkhash(kh, pk_data);
}

const unsigned char* eth_pubkey_khash_getaddress(const eth_pubkey_khash* kh) {
    return kh->data+12;
}

static int minth_util_hexchartoi(char c) {
    static int hextable[] = {[(unsigned char) '0']=0, [(unsigned char) '1']=1, 
                             [(unsigned char) '2']=2, [(unsigned char) '3']=3, 
                             [(unsigned char) '4']=4, [(unsigned char) '5']=5,
                             [(unsigned char) '6']=6, [(unsigned char) '7']=7, 
                             [(unsigned char) '8']=8, [(unsigned char) '9']=9, 
                             [(unsigned char) 'A']=10, [(unsigned char) 'B']=11,
                             [(unsigned char) 'C']=12, [(unsigned char) 'D']=13, 
                             [(unsigned char) 'E']=14, [(unsigned char) 'F']=15};
    return hextable[(unsigned char) c];
}

static unsigned char minth_util_hexchartouchar(char c) {
    static unsigned char hextable[] = {[(unsigned char) '0']=0, [(unsigned char) '1']=1, 
                             [(unsigned char) '2']=2, [(unsigned char) '3']=3, 
                             [(unsigned char) '4']=4, [(unsigned char) '5']=5,
                             [(unsigned char) '6']=6, [(unsigned char) '7']=7, 
                             [(unsigned char) '8']=8, [(unsigned char) '9']=9, 
                             [(unsigned char) 'A']=10, [(unsigned char) 'B']=11,
                             [(unsigned char) 'C']=12, [(unsigned char) 'D']=13, 
                             [(unsigned char) 'E']=14, [(unsigned char) 'F']=15};
    return hextable[(unsigned char) c];
}

void minth_util_hexstringtobytes(unsigned char* bytes, const char* b, const char* e) {
    size_t i = 0;
    for(; e - b >= 2; b+=2, ++i) {
        bytes[i] |= (minth_util_hexchartouchar(*b)) << 4;
        bytes[i] |= minth_util_hexchartouchar(*(b + 1));
    }
    if(b != e) {
        //We have an odd number of bytes, write the last one
        bytes[i] |= (minth_util_hexchartouchar(*b)) << 4;
    }
}

void eth_pubkey_khash_writeeip55address(FILE* stream, const eth_pubkey_khash* kh) {
    char loweraddr[41];
    eth_util_bytestohexstring(loweraddr, eth_pubkey_khash_getaddress(kh), 20);
    minth_util_tolowerstr(loweraddr);    

    //Hash the lowercase address
    union ethash_hash256 ehash = ethash_keccak256((unsigned char*) loweraddr, 40);
    char ehash_digits[41];
    eth_util_bytestohexstring(ehash_digits, (unsigned char*) ehash.str, 20);

    //Finally, using the hash, write each char according to EIP-55, checking if
    //the character hex value of the hash is greater than 8
    for(int i = 0; i < 40; ++i) {
        if(isalpha(loweraddr[i]) && (minth_util_hexchartoi(ehash_digits[i]) >= 0x8)) {
            putc(toupper(loweraddr[i]), stream);
        } else {
            putc(loweraddr[i], stream);
        }
    }
}

void eth_pubkey_khash_eip55addresstostring(char* out, const eth_pubkey_khash* kh) {
    eth_util_bytestohexstring(out, eth_pubkey_khash_getaddress(kh), 20);
    minth_util_tolowerstr(out);

    //Hash the lowercase address
    union ethash_hash256 ehash = ethash_keccak256((unsigned char*) out, 40);

    //Finally, using the hash, write each char according to EIP-55, checking if
    //the character hex value of the hash is greater than 8
    for(int i = 0; i < 40; ++i) {
        if(isalpha(out[i]) && (minth_util_hexchartoi(ehash.str[i]) >= 0x8)) {
            out[i] = toupper(out[i]);
        }
    }
}

char* eth_util_bytestohexstring(char* out, const unsigned char* bytes, size_t bytes_sz) {
    static char hextable[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',
                              'B', 'C', 'D', 'E', 'F'};
    for(size_t i = 0; i < bytes_sz; ++i) {
        *out++ = hextable[(bytes[i] >> 4) & 0xF];
        *out++ = hextable[bytes[i] & 0xF];
    }
    *out++ = '\0';
    return out;
}

void eth_util_writebytestohex(FILE* stream, const unsigned char* bytes, size_t bytes_sz) {
    static char hextable[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',
                              'B', 'C', 'D', 'E', 'F'};
    for(size_t i = 0; i < bytes_sz; ++i) {
        putc(hextable[(bytes[i] >> 4) & 0xF], stream);
        putc(hextable[bytes[i] & 0xF], stream);
    }
}

