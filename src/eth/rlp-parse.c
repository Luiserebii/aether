#include <stddef.h>
#include <assert.h>

#include "../../include/eth/rlp-parse.h"
#include <cstl/algorithm.h>

void minth_rlp_t_parse_rlp_t(struct minth_rlp_t_parsing_data* pd) {
    if(*pd->b == '[') {
        if(pd->e - pd->b == 2) {
            assert(*(pd->e - 1) == ']');
            pd->token_type = MINTH_RLP_T_LIST_EMPTY_TOKEN;
        } else {
            pd->token_type = MINTH_RLP_T_LIST_FULL_TOKEN;
        }
    } else if(*pd->b == '0') {
        assert(*(pd->b + 1) == 'x');
        if(pd->e - pd->b == 2) {
            assert(*(pd->e-1) == 'x');
            pd->token_type = MINTH_RLP_T_BYTE_ARRAY_EMPTY_TOKEN;
        } else {
            pd->token_type = MINTH_RLP_T_BYTE_ARRAY_FULL_TOKEN;
        }
    }
}

void minth_rlp_t_parse_rlp_t_list_full(struct minth_rlp_t_parsing_data* pd) {
    ++pd->b;
    --pd->e;
    pd->token_type = MINTH_RLP_T_LIST_ELEMENTS_TOKEN;
}

/**
 * Takes elements and returns the first found element into pd.
 * Returns a pointer to the next element after the comma;
 * returns a pointer to the end if it is the last element otherwise.
 */
const char* minth_rlp_t_parse_rlp_t_elements(struct minth_rlp_t_parsing_data* pd) {
    //Skip whitespace
    for(; *pd->b == ' '; ++pd->b)
        ;
    //If we have a [, we want to recursively find the last.
    if(*pd->b == '[') {
        const char* t = pd->b + 1;
        for(size_t bracket_stack = 1; bracket_stack > 0 && t != pd->e; ++t) {
            if(*t == '[') {
                ++bracket_stack;
            } else if(*t == ']') {
                --bracket_stack;
            }
        }
        const char* end = pd->e;
        pd->e = t;

        //If there are more commas afterwards, return after, else end
        const char* comm; 
        algorithm_find(pd->e, end, ',', comm);
        return comm == end ? end : comm + 1;
            
    } else {
        const char* end = pd->e;
        algorithm_find(pd->b, end, ',', pd->e);
        if(pd->e == end) {
            //Move back from any whitespace
            for(; *(pd->e - 1) == ' '; --pd->e)
                ;
            return end;
        } else {
            return pd->e + 1;
        }
    }
}
