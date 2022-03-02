/* Creates file that is 5 bytes. Seeks past end of file and attempts to write one byte to file. It should write 0 bytes to pass the test.  */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  int handle, byte_cnt;
  char buf[] = "testingSeek";
  CHECK(create("testing.txt", 5), "created testing.txt");
  CHECK((handle = open("testing.txt")) > 1, "open \"testing.txt\"");
  seek(handle, 1000);
  byte_cnt = write(handle, &buf, 1);
  if (byte_cnt != 0)
    fail("write() returned %d instead of 0", byte_cnt);
}
