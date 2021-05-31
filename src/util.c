#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>

#include <gmp.h>

void aether_util_tolowerstr(char* str) {
    while((*str = tolower(*str)) && ++str)
        ;
}

int aether_util_hexchartoi(char c) {
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

unsigned char aether_util_hexchartouchar(char c) {
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

void aether_util_hexstringtobytes(unsigned char* bytes, const char* b, const char* e) {
    size_t i = 0;
    for(; e - b >= 2; b+=2, ++i) {
        bytes[i] |= (aether_util_hexchartouchar(*b)) << 4;
        bytes[i] |= aether_util_hexchartouchar(*(b + 1));
    }
    if(b != e) {
        //We have an odd number of bytes, write the last one
        bytes[i] |= (aether_util_hexchartouchar(*b)) << 4;
    }
}

char* aether_util_bytestohexstring(char* out, const unsigned char* bytes, size_t bytes_sz) {
    static char hextable[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',
                              'B', 'C', 'D', 'E', 'F'};
    for(size_t i = 0; i < bytes_sz; ++i) {
        *out++ = hextable[(bytes[i] >> 4) & 0xF];
        *out++ = hextable[bytes[i] & 0xF];
    }
    *out++ = '\0';
    return out;
}

void aether_util_writebytestohex(FILE* stream, const unsigned char* bytes, size_t bytes_sz) {
    static char hextable[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',
                              'B', 'C', 'D', 'E', 'F'};
    for(size_t i = 0; i < bytes_sz; ++i) {
        putc(hextable[(bytes[i] >> 4) & 0xF], stream);
        putc(hextable[bytes[i] & 0xF], stream);
    }
}

unsigned long long aether_util_scalarstring_to_ull(const char* first, const char* end) {
    unsigned long long n = 0;
    unsigned long long mult = 1;
    for(; first != end ; mult *= 10, --end) {
        assert(isdigit(*(end - 1)));
        n += (*(end - 1) - '0') * mult;
    }
    return n;
}

void aether_util_uchar_ptr_swap(unsigned char* first, unsigned char* last) {
    unsigned char t = *first;
    *first = *last;
    *last = t;
}

void aether_util_uchar_arr_reverse(unsigned char* first, unsigned char* last) {
    while((first != last) && first != --last) {
        aether_util_uchar_ptr_swap(first++, last);
    }
}

unsigned char aether_util_big_endian_bytes_size(unsigned long long n) {
    unsigned long long cnt = 0;
    for(; n > 0x0; ++cnt) {
        n >>= 8;
    }
    return cnt;
}

int aether_util_uchar_arr_iszero(const unsigned char* first, const unsigned char* last) {
    for(; first != last; ++first) {
        if(*first != 0) {
            return 0;
        }
    }
    return 1;
}

void aether_util_mpz_import(mpz_t rop, size_t sz, const void* bytes) {
    mpz_import(rop, sz, 1, 1, 1, 0, bytes);
} 

void aether_util_mpz_export(void* rop, size_t sz, const mpz_t op) {
    size_t bytes_w;
    mpz_export(rop, &bytes_w, 1, 1, 1, 0, op);
    assert(bytes_w <= sz);
    if(bytes_w != sz) {
        memmove(rop + sz - bytes_w, rop, bytes_w);
        memset(rop, 0, sz - bytes_w);
    }
}
