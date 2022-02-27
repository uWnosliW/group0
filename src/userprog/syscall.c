#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "lib/string.h"

/* Global file operation lock (to be removed later) */
static lock_t global_file_lock;

static void syscall_handler(struct intr_frame*);

void syscall_init(void) {
  lock_init(&global_file_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

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

      thread_current()->pcb->status->exit_code = args[1];

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

      if (!is_valid_string((char*)args[1])) {
        lock_release(&global_file_lock);
        printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
        f->eax = -1;
        process_exit();
        break;
      }

      f->eax = filesys_create((char*)args[1], args[2]);

      lock_release(&global_file_lock);
      break;
    }

    case SYS_REMOVE: {
      lock_acquire(&global_file_lock);

      if (!is_valid_string((char*)args[1])) {
        lock_release(&global_file_lock);
        printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
        f->eax = -1;
        process_exit();
        break;
      }

      f->eax = filesys_remove((char*)args[1]);

      lock_release(&global_file_lock);
      break;
    }

    case SYS_OPEN: {
      lock_acquire(&global_file_lock);

      if (!is_valid_string((char*)args[1])) {
        lock_release(&global_file_lock);
        printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
        f->eax = -1;
        process_exit();
        break;
      }

      struct file* file_ptr = filesys_open((char*)args[1]);
      if (file_ptr == NULL) {
        f->eax = -1;
      } else {
        struct list* fd_table_ptr = &thread_current()->pcb->fd_table;
        struct fd_table_entry* curr_fd;
        uint32_t fd_num = 2;

        struct list_elem *prev = list_head(fd_table_ptr), *curr;
        for (curr = list_begin(fd_table_ptr); curr != list_end(fd_table_ptr);
             curr = list_next(curr)) {
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
      lock_acquire(&global_file_lock);

      struct fd_table_entry* fdt_entry = get_fd_table_entry(args[1]);

      if (fdt_entry == NULL) {
        f->eax = -1;
      } else {
        f->eax = file_length(fdt_entry->file);
      }

      lock_release(&global_file_lock);
      break;
    }

    case SYS_READ: {
      lock_acquire(&global_file_lock);

      if (args[1] == STDIN_FILENO) {
        lock_release(&global_file_lock);

        char* casted_buffer = (char*)args[2];
        size_t bytes_to_read = args[3], bytes_read = 0;

        uint8_t c;
        while (bytes_read < bytes_to_read) {
          c = input_getc();
          casted_buffer[bytes_read] = c;
          bytes_read++;
        }

        f->eax = bytes_read;
        break;
      }

      if (!is_valid_string((char*)args[2])) {
        lock_release(&global_file_lock);
        printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
        f->eax = -1;
        process_exit();
        break;
      }

      struct fd_table_entry* fdt_entry = get_fd_table_entry(args[1]);

      if (fdt_entry == NULL) {
        f->eax = -1;
      } else {
        f->eax = file_read(fdt_entry->file, (void*)args[2], (off_t)args[3]);
      }

      lock_release(&global_file_lock);
      break;
    }

    case SYS_WRITE: {
      lock_acquire(&global_file_lock);

      if (!is_valid_user_address((void*)args[2], args[3])) {
        lock_release(&global_file_lock);
        printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
        f->eax = -1;
        process_exit();
      }

      if (args[1] == STDOUT_FILENO) {
        lock_release(&global_file_lock);

        char* buffer = (char*)args[2];
        size_t bytes_left = args[3];

        while (bytes_left > 0) {
          if (bytes_left < 256) {
            putbuf(buffer, bytes_left);
            bytes_left = 0;
          } else {
            putbuf(buffer, 256);
            buffer += 256;
            bytes_left -= 256;
          }
        }

        f->eax = args[3];
        break;
      }

      struct fd_table_entry* fdt_entry = get_fd_table_entry(args[1]);

      if (fdt_entry == NULL) {
        f->eax = -1;
      } else {
        char* buffer = (char*)args[2];
        size_t bytes_left = args[3], bytes_written;

        while (bytes_left > 0) {
          if (bytes_left < 256) {
            bytes_written = file_write(fdt_entry->file, buffer, bytes_left);
          } else {
            bytes_written -= file_write(fdt_entry->file, buffer, 256);
          }
          buffer += bytes_written;
          bytes_left -= bytes_written;
        }

        f->eax = args[3];
      }

      lock_release(&global_file_lock);
      break;
    }

    case SYS_SEEK: {
      lock_acquire(&global_file_lock);

      struct fd_table_entry* fdt_entry = get_fd_table_entry(args[1]);

      if (fdt_entry != NULL) {
        fdt_entry->file->pos = args[2];
      }

      lock_release(&global_file_lock);
      break;
    }

    case SYS_TELL: {
      lock_acquire(&global_file_lock);

      struct fd_table_entry* fdt_entry = get_fd_table_entry(args[1]);

      if (fdt_entry == NULL) {
        f->eax = -1;
      } else {
        f->eax = fdt_entry->file->pos;
      }

      lock_release(&global_file_lock);
      break;
    }

    case SYS_CLOSE: {
      lock_acquire(&global_file_lock);

      struct fd_table_entry* fdt_entry = get_fd_table_entry(args[1]);

      if (fdt_entry == NULL) {
        f->eax = -1;
      } else {
        file_close(fdt_entry->file);
      }

      lock_release(&global_file_lock);
      break;
    }

    case SYS_COMPUTE_E: {
      // TODO
      break;
    }

    case SYS_PRACTICE: {
      f->eax = args[1] + 1;
      break;
    }

    default: { PANIC("Syscall is not implemented"); }
  }
}
