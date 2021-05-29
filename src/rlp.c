#include <aether/rlp-parse.h>
#include <aether/rlp.h>
#include <aether/vector-rlp-t.h>
#include <aether/vector-uchar.h>
#include <aether/util.h>

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <ctype.h>

void aether_rlp_t_init_list(struct aether_rlp_t* t) {
    vector_rlp_t_init(&t->value.list);
    t->tag = AETHER_RLP_T_LIST;
}

void aether_rlp_t_init_list_empty(struct aether_rlp_t* t) {
    vector_rlp_t_init(&t->value.list);
    t->tag = AETHER_RLP_T_LIST;
}

void aether_rlp_t_init_byte_array_empty(struct aether_rlp_t* t) {
    vector_uchar_init(&t->value.byte_array);
    t->tag = AETHER_RLP_T_BYTE_ARR;
}

void aether_rlp_t_init_byte_array_range(struct aether_rlp_t* t, const unsigned char* first, const unsigned char* last) {
    vector_uchar_init_range(&t->value.byte_array, first, last);
    t->tag = AETHER_RLP_T_BYTE_ARR;
}

void aether_rlp_t_init_byte_array_hexstring(struct aether_rlp_t* t, const char* first, const char* last) {
    //Calculate amount of space needed and initialize
    //This is probably a better fit for a function of vector_uchar
    size_t sz = ceil(((double)(last-first)/2));
    vector_uchar_init_size(&t->value.byte_array, sz);
    memset(t->value.byte_array.head, 0, sz);
    aether_util_hexstringtobytes(t->value.byte_array.head, first, last);
    t->tag = AETHER_RLP_T_BYTE_ARR;
}

void aether_rlp_t_init_byte_array_scalarstring(struct aether_rlp_t* t, const char* first, const char* last) {
    unsigned long long n = aether_util_scalarstring_to_ull(first, last);
    if(!n) {
        vector_uchar_init_size(&t->value.byte_array, 1);
        *(vector_uchar_begin(&t->value.byte_array)) = 128U;
    } else {
        vector_uchar_init(&t->value.byte_array);
        vector_uchar_insert_big_endian_bytes(&t->value.byte_array, n);
    }
    t->tag = AETHER_RLP_T_BYTE_ARR;
}

void aether_rlp_t_init_from_string(struct aether_rlp_t* t, const char* rlp_str) {
    const char* rlp_str_begin = rlp_str;
    for(; *rlp_str; ++rlp_str)
        ;
    aether_rlp_t_init_from_string_range(t, rlp_str_begin, rlp_str);
}

void aether_rlp_t_init_from_string_range(struct aether_rlp_t* t, const char* rlp_str_b, const char* rlp_str_e) {
    struct aether_rlp_t_parsing_data pd = {rlp_str_b, rlp_str_e, 0};
    aether_rlp_t_parse_rlp_t(&pd);
    switch(pd.token_type) {
        case AETHER_RLP_T_LIST_EMPTY_TOKEN:
            aether_rlp_t_init_list_empty(t);
            break;
        case AETHER_RLP_T_BYTE_ARRAY_EMPTY_TOKEN:
            aether_rlp_t_init_byte_array_empty(t);
            break;
        case AETHER_RLP_T_BYTE_ARRAY_FULL_TOKEN:
            aether_rlp_t_init_byte_array_hexstring(t, pd.b + 2, pd.e);
            break;
        case AETHER_RLP_T_LIST_FULL_TOKEN:
            aether_rlp_t_parse_rlp_t_list_full(&pd);
            aether_rlp_t_init_list(t);
            //Obtain each element and then do the thing lol
            const char* end = pd.e;
            struct aether_rlp_t e;
            for(;;) {
                const char* ret = aether_rlp_t_parse_rlp_t_elements(&pd);
                aether_rlp_t_init_from_string_range(&e, pd.b, pd.e);
                vector_rlp_t_push_back(&t->value.list, e);
                if(ret == end) {
                    break;
                } else {
                    pd.b = ret;
                    pd.e = end;
                }
            }
            break;
        case AETHER_RLP_T_SCALAR_TOKEN:
            aether_rlp_t_init_byte_array_scalarstring(t, pd.b, pd.e);
            break;
        default:
            assert(0);
            break;
    }
}

unsigned long long aether_rlp_t_serialized_total_sz(const struct aether_rlp_t* rlp) {
    switch(rlp->tag) {
        case AETHER_RLP_T_BYTE_ARR: {
            const vector_uchar* byte_array = &rlp->value.byte_array;
            size_t sz = vector_uchar_size(byte_array);
            if(sz == 1 && *(vector_uchar_begin(byte_array)) < 128U) {
                return 1;
            } else if(sz < 56) {
                return sz + 1;
            } else {
                assert(sz < 18446744073709551615U);
                return sz + 1 + aether_util_big_endian_bytes_size(sz);
            }
            break;
        }
        case AETHER_RLP_T_LIST: {
            const vector_rlp_t* list = &rlp->value.list;
            size_t sz = vector_rlp_t_list_items_serialized_total_sz(list);
            if(sz < 56) {
                return sz + 1;
            } else {
                return sz + 1 + aether_util_big_endian_bytes_size(sz);
            }
            break;
        }
        default:
            assert(0);
            break;
    }
}

/**
 * Future note: the below code may break with current vector_uchar: although size_t may be 64 bytes, 
 * systems with a smaller size_t can cause large enough byte arrays to break. Consider an alternate
 * solution for these systems (probably with a value held in unsigned long long int)
 */

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
void aether_rlp_t_encode(const struct aether_rlp_t* t, vector_uchar* rlp_out) {
    switch(t->tag) {
        case AETHER_RLP_T_BYTE_ARR: {
            const vector_uchar* src_bytes = &t->value.byte_array;
            size_t sz = vector_uchar_size(src_bytes);
            if(sz == 1 && *(vector_uchar_begin(src_bytes)) < 128U) {
                vector_uchar_push_back(rlp_out, *(vector_uchar_begin(src_bytes)));            
            } else if(sz < 56) {
                vector_uchar_push_back(rlp_out, 128U + sz);
                vector_uchar_insert_range(rlp_out, vector_uchar_end(rlp_out), vector_uchar_begin(src_bytes), vector_uchar_end(src_bytes));
            } else {
                assert(sz < 18446744073709551615U);
                vector_uchar_push_back(rlp_out, 183U + aether_util_big_endian_bytes_size(sz));
                vector_uchar_insert_big_endian_bytes(rlp_out, sz);
                vector_uchar_insert_range(rlp_out, vector_uchar_end(rlp_out), vector_uchar_begin(src_bytes), vector_uchar_end(src_bytes));
            }
            break;
        }
        case AETHER_RLP_T_LIST: {
            const vector_rlp_t* list = &t->value.list;
            const unsigned long long sz = vector_rlp_t_list_items_serialized_total_sz(list);
            if(sz < 56) {
                vector_uchar_push_back(rlp_out, 192U + sz);
                const struct aether_rlp_t* end = vector_rlp_t_end(list);
                for(const struct aether_rlp_t* item = vector_rlp_t_begin(list); item != end; ++item) {
                    aether_rlp_t_encode(item, rlp_out);
                }
            } else {
                assert(sz < 18446744073709551615U);
                vector_uchar_push_back(rlp_out, 247U + aether_util_big_endian_bytes_size(sz));
                vector_uchar_insert_big_endian_bytes(rlp_out, sz);
                const struct aether_rlp_t* end = vector_rlp_t_end(list);
                for(const struct aether_rlp_t* item = vector_rlp_t_begin(list); item != end; ++item) {
                    aether_rlp_t_encode(item, rlp_out);
                }
            }
            break;
        }
    }
}

void aether_rlp_t_deinit(struct aether_rlp_t* t) {
    switch(t->tag) {
        case AETHER_RLP_T_BYTE_ARR:
            vector_uchar_deinit(&t->value.byte_array);
            break;
        case AETHER_RLP_T_LIST: {
            struct aether_rlp_t* b = vector_rlp_t_begin(&t->value.list);
            struct aether_rlp_t* e = vector_rlp_t_end(&t->value.list);
            for(; b != e; ++b) {
                aether_rlp_t_deinit(b);
            }
            vector_rlp_t_deinit(&t->value.list);
            break;
        }
    }
}

/*********************************
 * rlp_t member helper functions
 *********************************/

void vector_uchar_insert_big_endian_bytes(vector_uchar* out, unsigned long long n) {
    //Size and not pointer, as pointer could be invalidated if reallocated
    //on push_back!
    size_t sz = vector_uchar_size(out);
    for(; n > 0x0; n >>= 8) {
        vector_uchar_push_back(out, n & 0xFF);
    }
    aether_util_uchar_arr_reverse(vector_uchar_begin(out) + sz, vector_uchar_end(out));
}

unsigned long long vector_rlp_t_list_items_serialized_total_sz(const vector_rlp_t* list) {
    size_t sz = 0;
    //Count serializations
    const struct aether_rlp_t* end = vector_rlp_t_end(list);
    for(const struct aether_rlp_t* item = vector_rlp_t_begin(list); item != end; ++item) {
        sz += aether_rlp_t_serialized_total_sz(item);
    }
    return sz;
}

