#ifndef AETHER_KECCAK256_H
#define AETHER_KECCAK256_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

/**
 * keccak256 hash data type.
 */
typedef struct {
    unsigned char data[32];
} aether_keccak256_hash;

/**
 * Calculates the keccak256 hash from any arbitrary data, reading sz bytes.
 */
void aether_keccak256_bhash(aether_keccak256_hash* kh, const unsigned char* data, size_t sz);

#ifdef __cplusplus
}
#endif

#endif
