#ifndef __LIB_UT_H
#define __LIB_UT_H

#include <stddef.h>

void *malloc_and_init(size_t size, void (*init)(void *obj));

#endif
