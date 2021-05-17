#include <aether/eth/rlp-parse.h>
#include <aether/eth/rlp.h>
#include <aether/eth/vector-rlp-t.h>

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <assert.h>

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
        default:
            assert(0);
            break;
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
