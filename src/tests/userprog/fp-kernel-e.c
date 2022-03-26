/* Verifies that the compute_e system call is implemented correctly */

#include "tests/lib.h"
#include "tests/main.h"
#include <float.h>
#include <syscall.h>

const char *test_name = "fp-kernel-e";

void test_main(void) {
  msg("Computing e...");
  double e_res = compute_e(10);
  if (abs_val(e_res - E_VAL) < TOL) {
    msg("Success!");
    exit(162);
  } else {
    msg("Got e=%f, expected e=%f", e_res, E_VAL);
    exit(126);
  }
}
