#ifndef CSTL_MEMORY
#define CSTL_MEMORY

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

void* cstl_malloc(size_t sz);
void* cstl_realloc(void* ptr, size_t sz);
void cstl_free(void* ptr);

#ifdef __cplusplus
}
#endif

#endif
