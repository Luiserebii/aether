#ifndef MINTH_RLP_H
#define MINTH_RLP_H

#ifdef __cplusplus
extern "C" {
#endif

#include "./vector-rlp-t.h"
#include "./vector-uchar.h"
#include "./eth.h"
#include <assert.h>
#include <math.h>
#include <cstl/algorithm.h>

enum minth_rlp_t_tag { MINTH_RLP_T_LIST, MINTH_RLP_T_BYTE_ARR };

struct minth_rlp_t {
    union {
        vector_rlp_t list;
        vector_uchar byte_array;
    } value;
    enum minth_rlp_t_tag tag;
};

/***/

/**
 * Initialize a minth_rlp_t as a list (L).
 */
void minth_rlp_t_init_list(struct minth_rlp_t* t);

/**
 * Initialize a minth_rlp_t as an empty list (L).
 *
 * It should be noted that the implementation is no different from simply
 * initializing a minth_rlp_t as a list, but it's more expressive this way.
 */
void minth_rlp_t_init_list_empty(struct minth_rlp_t* t);

/**
 * Initialize a minth_rlp_t as an empty byte array (B).
 */
void minth_rlp_t_init_byte_array_empty(struct minth_rlp_t* t);

/**
 * Initialize a minth_rlp_t as a byte array (B) with [first, last) 
 * unsigned char* bytes.
 */
void minth_rlp_t_init_byte_array_range(struct minth_rlp_t* t, const unsigned char* first, const unsigned char* last);

/**
 * Initialize a minth_rlp_t as a byte_array (B) with a hex string
 * of [first, last) range.
 */
void minth_rlp_t_init_byte_array_hexstring(struct minth_rlp_t* t, const char* first, const char* last);

/**
 * Initialize a minth_rlp_t from a c-string.
 * See minth_rlp_t_init_from_string.
 */
void minth_rlp_t_init_from_string(struct minth_rlp_t* t, const char* rlp_str);

/**
 * Initialize a minth_rlp_t from a string formatted under the following rules:
 *    * [] represents the delimiters of a list
 *    * 0x represents the prefix delimiter of a byte array
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
 */
void minth_rlp_t_init_from_string_range(struct minth_rlp_t* t, const char* rlp_str_b, const char* rlp_str_e);

/**
 * Deinitializes a minth_rlp_t, recursively calling it if needed.
 */
void minth_rlp_t_deinit(struct minth_rlp_t* t);

#ifdef __cplusplus
}
#endif

#endif
