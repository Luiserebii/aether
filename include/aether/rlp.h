#ifndef AETHER_RLP_H
#define AETHER_RLP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <aether/vector/vector-rlp-t.h>
#include <aether/vector/vector-uchar.h>
#include <aether/eth.h>
#include <aether/tx.h>

enum aether_rlp_t_tag { AETHER_RLP_T_LIST, AETHER_RLP_T_BYTE_ARR };

struct aether_rlp_t {
    union {
        struct aether_vector_rlp_t list;
        struct aether_vector_uchar byte_array;
    } value;
    enum aether_rlp_t_tag tag;
};

/***/

/**
 * Initialize a aether_rlp_t as a list (L).
 */
void aether_rlp_t_init_list(struct aether_rlp_t* t);

/**
 * Initialize a aether_rlp_t as an empty list (L).
 *
 * It should be noted that the implementation is no different from simply
 * initializing a aether_rlp_t as a list, but it's more expressive this way.
 */
void aether_rlp_t_init_list_empty(struct aether_rlp_t* t);

/**
 * Initialize a aether_rlp_t as an empty byte array (B).
 */
void aether_rlp_t_init_byte_array_empty(struct aether_rlp_t* t);

/**
 * Initialize a aether_rlp_t as a byte array (B) with [first, last) 
 * unsigned char* bytes.
 */
void aether_rlp_t_init_byte_array_range(struct aether_rlp_t* t, const unsigned char* first, const unsigned char* last);

/**
 * Initialize a aether_rlp_t as a byte_array (B) with a hex string
 * of [first, last) range.
 */
void aether_rlp_t_init_byte_array_hexstring(struct aether_rlp_t* t, const char* first, const char* last);

/**
 * Initialize a aether_rlp_t as a byte_array (B) with a scalar string
 * of [first, last) range.
 */
void aether_rlp_t_init_byte_array_scalarstring(struct aether_rlp_t* t, const char* first, const char* last);

/**
 * Initialize a aether_rlp_t as a byte_array (B) with a scalar unsigned
 * long long.
 */
void aether_rlp_t_init_byte_array_scalarull(struct aether_rlp_t* t, unsigned long long n);

/**
 * Initialize a aether_rlp_t as a byte_array (B) with a scalar byte array.
 * This scalar byte array may have leading zeros.
 */
void aether_rlp_t_init_byte_array_scalarbytes(struct aether_rlp_t* t, const unsigned char* first, const unsigned char* last);

/**
 * Initialize a aether_rlp_t as a byte_array (B) with an aether_eth_address.
 * This uses the encoding as specified in the Ethereum yellowpaper, where a
 * zero address is simply an empty byte array (B0).
 */
void aether_rlp_t_init_byte_array_address(struct aether_rlp_t* t, const aether_eth_address* addr);

/**
 * Initialize a aether_rlp_t from a c-string.
 * See aether_rlp_t_init_from_string.
 */
void aether_rlp_t_init_from_string(struct aether_rlp_t* t, const char* rlp_str);

/**
 * Initialize a aether_rlp_t from a string formatted under the following rules:
 *    * [] represents the delimiters of a list
 *    * 0x represents the prefix delimiter of a byte array
 *    * Numerical digits in decimal represent a scalar
 *    * Spaces must not be avaliable at the beginning or the end of the string.
 *      *rlp_str_b and *rlp_str_e must be delimiters or non-whitespace 
 *      characters.
 *    * Spaces may exist within the outermost delimiters of a list, and between
 *      list items.
 *    * , represents the item delimiters of a list
 *
 * Examples:
 *    * 0x1029
 *    * [0xE4B29A0]
 *    * [] (Empty list)
 *    * 0x (Empty byte array)
 *    * [0xA194,[],[[],0x293821B,0x843CA] 
 *    * [0,124,0x,0x129A] 
 */
void aether_rlp_t_init_from_string_range(struct aether_rlp_t* t, const char* rlp_str_b, const char* rlp_str_e);

/**
 * Initializes a aether_rlp_t using a constructed aether_eth_tx, i.e., using a 
 * transaction.
 */
void aether_rlp_t_init_tx(struct aether_rlp_t* t, const struct aether_eth_tx* tx);

/**
 * Sets the initialized aether_rlp_t byte array to the unsigned long long n.
 */
void aether_rlp_t_set_byte_array_scalarull(struct aether_rlp_t* t, unsigned long long n);

/**
 * Sets the initialized aether_rlp_t byte array to the scalar byte array passed.
 * This scalar byte array may have leading zeros.
 */
void aether_rlp_t_set_byte_array_scalarbytes(struct aether_rlp_t* t, const unsigned char* first, const unsigned char* last);

/**
 * Returns the total serialized byte size of the RLP_T.
 *
 * Note that if the byte size is over 2^64-1, i.e. the RLP is
 * invalid in this way, the behavior is undefined.
 */
size_t aether_rlp_t_serialized_total_sz(const struct aether_rlp_t* rlp);

/**
 * If the value to be serialised is a byte array, the RLP serialisation takes one of three forms:
 *    •If the byte array contains solely a single byte and that single byte is less than 128, then the input is exactly equal to the output.
 *    •If the byte array contains fewer than 56 bytes, then the output is equal to the input prefixed by the byte equal to the length of the byte array plus 128.
 *    •Otherwise, the output is equal to the input, provided that it contains fewer than 2^64 bytes, prefixed by the minimal-length byte array which when interpreted as a big-endian integer is equal to the length of the input byte array, which is itself prefixed by the number of bytes required to faithfully encode this length value plus 183.
 *
 * If instead, the value to be serialised is a sequence of other items then the RLP serialisation takes one of two forms:
 *    •If the concatenated serialisations of each contained item is less than 56 bytes in length, then the output is equal to that concatenation prefixed by the byte equal to the length of this byte array plus 192.
 *    •Otherwise, the output is equal to the concatenated serialisations, provided that they contain fewer than 2^64 bytes, prefixed by the minimal-length byte array which when interpreted as a big-endian integer is equal to the length of the concatenated serialisations byte array, which is itself prefixed by the number of bytes required to faithfully encode this length value plus 247.
 *
 */
void aether_rlp_t_encode(const struct aether_rlp_t* t, struct aether_vector_uchar* rlp_out);

/**
 * Deinitializes a aether_rlp_t, recursively calling it if needed.
 */
void aether_rlp_t_deinit(struct aether_rlp_t* t);

/*********************************
 * rlp_t member helper functions
 *********************************/

/**
 * Writes n as a big endian integer appended to aether_vector_uchar* out.
 * 8 bits are written across each element of the vector.
 */
void aether_vector_uchar_insert_big_endian_bytes(struct aether_vector_uchar* out, unsigned long long n);

/**
 * Returns the total serialized byte size of the RLP list items.
 *
 * Note that if the byte size is over 2^64-1, i.e. the RLP is
 * invalid in this way, the behavior is undefined.
 */
size_t aether_vector_rlp_t_list_items_serialized_total_sz(const struct aether_vector_rlp_t* list);

#ifdef __cplusplus
}
#endif

#endif
