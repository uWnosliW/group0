/* Creates file, seeks 10 bytes, writes 10 bytes, and then checks if tell returns the right index which is 20. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  int handle, byte_cnt;
  char buf[] = "testingTell";
  CHECK(create("testing.txt", 100), "created testing.txt");
  CHECK((handle = open("testing.txt")) > 1, "open \"testing.txt\"");

  seek(handle, 10);

  byte_cnt = write(handle, &buf, 10);
  if (byte_cnt < 10)
    fail("write() returned %d instead of 10", byte_cnt);

  int pos = tell(handle);
  if (pos != 20) {
    fail("tell() returned %d instead of 20", pos);
  }
}
