#include <malloc.h>
#include <ut.h>

void* malloc_and_init(size_t size, void (*init)(void* obj)) {
  void* obj = malloc(size);
  init(obj);
  return obj;
}
