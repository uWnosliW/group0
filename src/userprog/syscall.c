#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "lib/string.h"

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
    case SYS_HALT: {
      shutdown_power_off();
      break;
    }

    case SYS_EXIT: {
      f->eax = args[1];
      printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);

      thread_current()->pcb->status->exit_code = (int) args[1];

      process_exit();
      
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

    case SYS_WAIT: {
      // TODO
      break;
    }

    case SYS_CREATE: {
      lock_acquire(&global_file_lock);
      bool success = filesys_create((char *)args[1], args[2]);
      f->eax = success;
      lock_release(&global_file_lock);
      break;
    }

    case SYS_REMOVE: {
      lock_acquire(&global_file_lock);
      bool success = filesys_remove((char *)args[1]);
      f->eax = success;
      lock_release(&global_file_lock);
      break;
    }

    case SYS_OPEN: {
      lock_acquire(&global_file_lock);

      if (!is_valid_user_address((void *)args[1], 4)) {
        f->eax = -1;
        lock_release(&global_file_lock);
        break;
      }

      if (!is_valid_user_address((void *)args[1], strlen((char *)args[1]))) {
        f->eax = -1;
        lock_release(&global_file_lock);
        break;
      }

      struct file* file_ptr = filesys_open((char *)args[1]);
      if (file_ptr == NULL) {
        f->eax = -1;
      } else {
        struct list* fd_table_ptr = &thread_current()->pcb->fd_table;
        struct fd_table_entry* curr_fd;
        uint32_t fd_num = 0;

        struct list_elem* prev = list_head(fd_table_ptr), *curr;
        for (curr = list_begin(fd_table_ptr); curr != list_end(fd_table_ptr); curr = list_next(curr)) {
          curr_fd = list_entry(curr, struct fd_table_entry, elem);
          if (curr_fd->fd != fd_num) {
            break;
          }
          prev = curr;
          fd_num++;
        }

        struct fd_table_entry* new_fd = malloc(sizeof(struct fd_table_entry));
        new_fd->elem.prev = prev;
        new_fd->elem.next = curr;
        new_fd->fd = fd_num;
        new_fd->file = file_ptr;

        list_insert(curr, &new_fd->elem);

        f->eax = fd_num;
      }

      lock_release(&global_file_lock);
      break;
    }

    case SYS_FILESIZE: {
      // TODO
      break;
    }

    case SYS_READ: {
      f->eax = (uint32_t)file_read((struct file*)args[1], (void*)args[2], (off_t)args[3]);
      break;
    }

    case SYS_WRITE: {
      if(!is_valid_user_address((void *)args[2], args[3])) {
        f->eax = -1;
        process_exit();
      }
      putbuf((void *) args[2], (uint32_t) args[3]);
      f->eax = args[3];
      break;
    }
    
    case SYS_SEEK: {
      // TODO
      break;
    }
    
    case SYS_TELL: {
      // TODO
      break;
    }
    
    case SYS_CLOSE: {
      // TODO
      break;
    }

    case SYS_COMPUTE_E: {
      // TODO
      break;
    }

    case SYS_PRACTICE: {
      // TODO
      break;
    }

    default: {
      PANIC("Syscall is not implemented");
    }
  }
}
