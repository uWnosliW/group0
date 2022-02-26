#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  switch (args[0]) {
    case SYS_EXIT: {
      f->eax = args[1];
      printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
      process_exit();
      break;
    }
    case SYS_OPEN: {
      f->eax = (uint32_t)filesys_open((char*)args[1]);
      break;
    }
    case SYS_HALT: {
      shutdown_power_off();
      break;
    }
    case SYS_EXEC: {
      pid_t child_pid = process_execute((char*)args[1]);
      if (child_pid == TID_ERROR) {
        f->eax = -1;
      }
      f->eax = child_pid;
      break;
    }
    case SYS_CLOSE: {
      // TODO
      break;
    }
    case SYS_WRITE: {
      if(!validAddress((void *)args[2], args[3])) {
        f->eax = -1;
        process_exit();
      }
      putbuf((void *) args[2], (uint32_t) args[3]);
      f->eax = args[3];
      break;
    }
    case SYS_READ: {
      f->eax = (uint32_t)file_read((struct file*)args[1], (void*)args[2], (off_t)args[3]);
      break;
    }
    default: {
      PANIC("Syscall is not implemented");
    }
  }
}
