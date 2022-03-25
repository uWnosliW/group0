/* Pushes to FPU registers, then exec's a process which does the same.
   Ensures that the exec'd process' FPU does not interfere with ours. */

#include "tests/lib.h"
#include "tests/main.h"
#include <syscall.h>

#define NUM_VALUES 4
const char *test_name = "fp-asm";
static int values[NUM_VALUES] = {1, 6, 2, 162};

void test_main(void) {
  msg("Starting...");
  push_values_to_fpu(values, NUM_VALUES);
  wait(exec("fp-asm-helper"));
  if (pop_values_from_fpu(values, NUM_VALUES))
    exit(162);
  else
    exit(126);
}
