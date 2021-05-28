#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

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

