#ifndef MINTH_RLP_PARSE_H
#define MINTH_RLP_PARSE_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Parsing grammar:
 *    * rlp-t:
 *        * rlp-t-list
 *        * rlp-byte-array
 *    * rlp-t-list:
 *        * rlp-t-list-empty
 *        * [rlp-t-list-elements]
 *    * rlp-t-list-empty:
 *        * []
 *    * rlp-t-list-elements:
 *        * rlp-t
 *        * rlp-t-list-elements,rlp-t
 *    * rlp-byte-array:
 *        * 0xrlp-bytes
 *    * rlp-bytes:
 *        * rlp-byte
 *        * rlp-bytesrlp-byte
 *    * rlp-byte: one of
 *        * 0 1 2 3 4 5 6 7 8 9 A B C D E F
 */
enum minth_rlp_t_parsing_token_type { MINTH_RLP_T_LIST_EMPTY_TOKEN, MINTH_RLP_T_LIST_FULL_TOKEN,
                                        MINTH_RLP_T_BYTE_ARRAY_EMPTY_TOKEN, 
                                        MINTH_RLP_T_BYTE_ARRAY_FULL_TOKEN,
                                        MINTH_RLP_T_LIST_ELEMENTS_TOKEN,
                                        MINTH_RLP_T_LIST_ELEMENT_TOKEN };
/**
 * A struct meant to shuffle data around containing valid parsed RLP tokens.
 *
 * [b, e) contains the character data for a parsed token.
 * token_type contains the data type for the kind of token.
 */
struct minth_rlp_t_parsing_data {
    const char* b;
    const char* e;
    enum minth_rlp_t_parsing_token_type token_type;
};

/**
 * Parses a MINTH_RLP_T, returning valid parsing data for one of the following
 * token types:
 *    * MINTH_RLP_T_BYTE_ARRAY_EMPTY_TOKEN
 *    * MINTH_RLP_T_BYTE_ARRAY_FULL_TOKEN
 *    * MINTH_RLP_T_LIST_EMPTY_TOKEN
 *    * MINTH_RLP_T_LIST_FULL_TOKEN
 */
void minth_rlp_t_parse_rlp_t(struct minth_rlp_t_parsing_data* pd);

/**
 * Parses a MINTH_RLP_T_LIST_FULL_TOKEN, returning valid parsing data
 * for the containing elements as a MINTH_RLP_T_LIST_ELEMENTS_TOKEN token.
 */
void minth_rlp_t_parse_rlp_t_list_full(struct minth_rlp_t_parsing_data* pd);

/**
 * Takes elements and returns the first found element into pd.
 * Returns a pointer to the next element after the comma;
 * returns a pointer to the end if it is the last element otherwise.
 */
const char* minth_rlp_t_parse_rlp_t_elements(struct minth_rlp_t_parsing_data* pd);

#ifdef __cplusplus
}
#endif

#endif
