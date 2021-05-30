#ifndef AETHER_UTIL_H
#define AETHER_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <gmp.h>

/**
 * Changes all characters in str to lowercase.
 */
void aether_util_tolowerstr(char* str);

/**
 * Returns the integer hexadecimal value of the character passed.
 */
int aether_util_hexchartoi(char c);

/**
 * Returns the unsigned char hexadecimal value of the character passed.
 */
unsigned char aether_util_hexchartouchar(char c);

/**
 * Writes the hex string along [b, e) to the byte array at bytes. Every two characters
 * are stored into a single element of the byte array. This function could very well
 * overrun the bytes buffer: **PLEASE** ensure that (e-b)/2 < the size of bytes.
 *
 * The unsigned char* bytes is required to be zero-initialized, otherwise the call
 * to this function will cause a bad write.
 */
void aether_util_hexstringtobytes(unsigned char* bytes, const char* b, const char* e);

/**
 * Writes bytes_sz * 2 + 1 characters to the char string located by out.
 * Note that this function will only write the 8-bit value of each byte,
 * ignoring any other values (therefore any char larger than 8-bits will
 * have those ignored).
 *
 * The one off the end of the string is returned. If out at the start of the
 * function were a, and out at the end were b, then the range of the written
 * string would thus be [a, b).
 *
 * Note that this function could very well overwrite the out buffer: **PLEASE**
 * ensure that out can store bytes_z * 2 + 1 characters.
 */
char* aether_util_bytestohexstring(char* out, const unsigned char* bytes, size_t bytes_sz);

/**
 * Writes bytes_sz * 2 + 1 characters to the FILE* located by stream.
 * Note that this function will only write the 8-bit value of each byte,
 * ignoring any other values (therefore any char larger than 8-bits will
 * have those ignored).
 */
void aether_util_writebytestohex(FILE* stream, const unsigned char* bytes, size_t bytes_sz);

/**
 * Reads the characters within [first, end) and returns the unsigned 64-bit
 * value there as an unsigned long long.
 */
unsigned long long aether_util_scalarstring_to_ull(const char* first, const char* end);

/**
 * Swaps values
 */
void aether_util_uchar_ptr_swap(unsigned char* first, unsigned char* last);

/**
 * Reverses the bytes from unsigned char* [first, last]
 */
void aether_util_uchar_arr_reverse(unsigned char* first, unsigned char* last);

/**
 * Returns the number of bytes required to encode the length of n,
 * encoded as a big endian integer across an 8-bit byte array.
 */
unsigned char aether_util_big_endian_bytes_size(unsigned long long n);

/**
 * Imports sz bytes, big endian, into the mpz_t rop passed.
 */
void aether_util_mpz_import(mpz_t rop, size_t sz, const void* bytes);

#ifdef __cplusplus
}
#endif

#endif
