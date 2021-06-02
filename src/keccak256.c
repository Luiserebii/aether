#include <stdlib.h>
#include <string.h>

#include <ethash/keccak.h>
#include <aether/keccak256.h>

void aether_keccak256_bhash(aether_keccak256_hash* kh, const unsigned char* data, size_t sz) {
    union ethash_hash256 ehash = ethash_keccak256(data, sz);
    memcpy(kh->data, ehash.str, 32);
}
