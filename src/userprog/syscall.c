#include "userprog/syscall.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include <float.h>
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>

/* Global file operation lock (to be removed later) */
static lock_t global_file_lock;

static void syscall_handler(struct intr_frame*);

void syscall_init(void) {
  lock_init(&global_file_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* print_and_exit - Helper method that sets the return value in the interrupt frame, prints the exit
 * message, and exits */
void print_and_exit(struct intr_frame* f, int exit_code) {
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, exit_code);
  f->eax = exit_code;
  thread_current()->pcb->status->exit_code = exit_code;
  process_exit();
}

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /* Check that args[0] is in user space and mapped */
  if (!is_valid_buffer((void*)args, 4))
    print_and_exit(f, -1);

  /* Grab pcb lock */
  // TODO: fix synch issues
  struct lock* pcb_lock_ptr = &thread_current()->pcb->pcb_lock;
  // lock_acquire(pcb_lock_ptr);

  switch (args[0]) {
    case SYS_HALT: {
      shutdown_power_off(); /* Shut down */
      break;
    }

    case SYS_EXIT: {
      /* Verify args[1] is in user space and mapped, else exit(-1) */
      if (!is_valid_buffer((void*)&args[1], 4)) {
        print_and_exit(f, -1);
      }

      /* Exit with the exit code passed in */
      print_and_exit(f, args[1]);
      break;
    }

    case SYS_EXEC: {
      /* Verify args[1] and the string it points to are in user space and mapped, else exit(-1) */
      if (!is_valid_buffer((void*)&args[1], 4) || !is_valid_string((char*)args[1])) {
        print_and_exit(f, -1);
        break;
      }

      /* Execute the executable in args[1], setting the return code to -1 on error or the PID of the
       * child if successful */
      pid_t child_pid = process_execute((char*)args[1]);
      if (child_pid == TID_ERROR) {
        f->eax = -1;
      }
      f->eax = child_pid;
      break;
    }

    case SYS_WAIT: {
      /* Verify args[1] and the string it points to are in user space and mapped, else exit(-1) */
      if (!is_valid_buffer((void*)&args[1], 4)) {
        print_and_exit(f, -1);
        break;
      }

      /* Wait on the process with PID args[1] and return the process' exit code after it finishes */
      f->eax = process_wait((pid_t)args[1]);
      break;
    }

    case SYS_CREATE: {
      lock_acquire(&global_file_lock); /* Acquire lock */
      lock_acquire(pcb_lock_ptr);

      /* Verify that the string passed in is valid, exit(-1) if not */
      if (!is_valid_string((char*)args[1])) {
        lock_release(&global_file_lock); /* Release lock */
        lock_release(pcb_lock_ptr);
        print_and_exit(f, -1);
      }

      /* Return the result of filesys_create with the arguments passed in */
      f->eax = filesys_create((char*)args[1], args[2]);

      lock_release(&global_file_lock); /* Release lock */
      lock_release(pcb_lock_ptr);
      break;
    }

    case SYS_REMOVE: {
      lock_acquire(&global_file_lock); /* Acquire lock */
      lock_acquire(pcb_lock_ptr);

      /* Verify that the string passed in is valid, exit(-1) if not */
      if (!is_valid_string((char*)args[1])) {
        lock_release(&global_file_lock); /* Release lock */
        lock_release(pcb_lock_ptr);
        print_and_exit(f, -1);
      }

      /* Return the result of filesys_remove with the arguments passed in */
      f->eax = filesys_remove((char*)args[1]);

      lock_release(&global_file_lock); /* Release lock */
      lock_release(pcb_lock_ptr);
      break;
    }

    case SYS_OPEN: {
      lock_acquire(&global_file_lock); /* Acquire lock */

      /* Verify that the string passed in is valid, exit(-1) if not */
      if (!is_valid_string((char*)args[1])) {
        lock_release(&global_file_lock); /* Release lock */
        print_and_exit(f, -1);
      }

      /* Try opening the file with name args[1] */
      struct file* file_ptr = filesys_open((char*)args[1]);

      if (file_ptr == NULL) {
        f->eax = -1; /* Set return code to -1 if unsuccessful */
      } else {
        lock_acquire(pcb_lock_ptr);

        /* Iterate through the file descriptor table to find the first open file descriptor id */
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

        /* Create a new file descriptor for the current file and insert it into the proper location
         * in the list */
        struct fd_table_entry* new_fd = malloc(sizeof(struct fd_table_entry));
        new_fd->elem.prev = prev;
        new_fd->elem.next = curr;
        new_fd->fd = fd_num;
        new_fd->file = file_ptr;

        list_insert(curr, &new_fd->elem);

        lock_release(pcb_lock_ptr);

        /* Return the file descriptor id of the new file descriptor */
        f->eax = fd_num;
      }

      lock_release(&global_file_lock); /* Release lock */
      break;
    }

    case SYS_FILESIZE: {
      lock_acquire(&global_file_lock); /* Acquire lock */

      /* Try getting the file descriptor with id args[1] */
      lock_acquire(pcb_lock_ptr);
      struct fd_table_entry* fdt_entry = get_fd_table_entry(args[1]);
      lock_release(pcb_lock_ptr);

      /* If not found, return -1, else return the result of file_length on the file descriptor's
       * file */
      if (fdt_entry == NULL) {
        f->eax = -1;
      } else {
        f->eax = file_length(fdt_entry->file);
      }

      lock_release(&global_file_lock); /* Release lock */
      break;
    }

    case SYS_READ: {
      lock_acquire(&global_file_lock); /* Acquire lock */

      if (args[1] == STDIN_FILENO) {
        lock_release(&global_file_lock); /* Release lock since we don't need it for stdin */

        /* In the special case of reading from stdin, call input_getc and populate the buffer at
         * args[2] until we've read enough bytes and return the amount of bytes we've read */
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

      /* If our buffer is not entirely in user memory and fully mapped, exit(-1) */
      if (!is_valid_buffer((void*)args[2], args[3])) {
        lock_release(&global_file_lock); /* Release lock */
        print_and_exit(f, -1);
      }

      /* Try getting the file descriptor with id args[1] */
      lock_acquire(pcb_lock_ptr);
      struct fd_table_entry* fdt_entry = get_fd_table_entry(args[1]);
      lock_release(pcb_lock_ptr);

      /* If not found, return -1, else return the result of file_read on the file descriptor's file
       */
      if (fdt_entry == NULL) {
        f->eax = -1;
      } else {
        f->eax = file_read(fdt_entry->file, (void*)args[2], (off_t)args[3]);
      }

      lock_release(&global_file_lock); /* Release lock */
      break;
    }

    case SYS_WRITE: {
      lock_acquire(&global_file_lock); /* Acquire lock */

      /* If our buffer is not entirely in user memory and fully mapped, exit(-1) */
      if (!is_valid_buffer((void*)args[2], args[3])) {
        lock_release(&global_file_lock); /* Release lock */
        print_and_exit(f, -1);
      }

      if (args[1] == STDOUT_FILENO) {
        lock_release(&global_file_lock); /* Release lock because we don't need it for stdout */

        /* In the special case of reading from stdin, call putbuf and populate the buffer at args[2]
         * min(bytes_left, 256) bytes at a time until we've written enough bytes and return the
         * amount of bytes we've read */
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

      lock_acquire(pcb_lock_ptr);
      struct fd_table_entry* fdt_entry = get_fd_table_entry(args[1]);
      lock_release(pcb_lock_ptr);

      if (fdt_entry == NULL) {
        f->eax = -1; /* If file descriptor not found, return -1 */
      } else {
        /* Create a new buffer of size args[3] and copy args[3] of the bytes from the buffer at
         * args[2] into it */
        char *original_buffer, *buffer;
        original_buffer = buffer = calloc(sizeof(char), args[3]);
        memcpy(buffer, (char*)args[2], args[3]);

        /* Read from fdt_entry->file and populate the buffer at args[2] min(bytes_left, 256) bytes
         * at a time until we've written enough bytes and return the amount of bytes we've read */
        size_t bytes_left = args[3], bytes_written, expected_bytes_written;

        f->eax = args[3];

        while (bytes_left > 0) {
          if (bytes_left < 256) {
            expected_bytes_written = bytes_left;
            bytes_written = file_write(fdt_entry->file, buffer, bytes_left);
          } else {
            expected_bytes_written = 256;
            bytes_written = file_write(fdt_entry->file, buffer, 256);
          }

          buffer += bytes_written;
          bytes_left -= bytes_written;

          if (bytes_written < expected_bytes_written) {
            f->eax -= bytes_left;
            break;
          }
        }

        /* Free the buffer we made after we're done */
        free(original_buffer);
      }

      lock_release(&global_file_lock); /* Release lock */
      break;
    }

    case SYS_SEEK: {
      lock_acquire(&global_file_lock); /* Acquire lock */

      /* Try getting the file descriptor with id args[1] */
      lock_acquire(pcb_lock_ptr);
      struct fd_table_entry* fdt_entry = get_fd_table_entry(args[1]);
      lock_release(pcb_lock_ptr);

      /* If found, change file descriptor's file's position to args[2] */
      if (fdt_entry != NULL) {
        file_seek(fdt_entry->file, args[2]);
      }

      lock_release(&global_file_lock); /* Release lock */
      break;
    }

    case SYS_TELL: {
      lock_acquire(&global_file_lock); /* Acquire lock */

      /* Try getting the file descriptor with id args[1] */
      struct fd_table_entry* fdt_entry = get_fd_table_entry(args[1]);

      /* If not found, return -1, else return the result of file_tell on the file descriptor's file
       */
      if (fdt_entry == NULL) {
        f->eax = -1;
      } else {
        f->eax = file_tell(fdt_entry->file);
      }

      lock_release(&global_file_lock); /* Release lock */
      break;
    }

    case SYS_CLOSE: {
      lock_acquire(&global_file_lock); /* Acquire lock */

      /* Try getting the file descriptor with id args[1] */
      struct fd_table_entry* fdt_entry = get_fd_table_entry(args[1]);

      /* If not found exit(-1) */
      if (fdt_entry == NULL) {
        lock_release(&global_file_lock); /* Release lock */
        print_and_exit(f, -1);
      }

      /* Close the file, remove it from the file descriptor, free the file descriptor */
      file_close(fdt_entry->file);
      list_remove(&fdt_entry->elem);
      free(fdt_entry);

      lock_release(&global_file_lock); /* Release lock */
      break;
    }

    case SYS_COMPUTE_E: {
      /* Return the result of calling sys_sum_to_e on args[1] */
      f->eax = sys_sum_to_e(args[1]);
      break;
    }

    case SYS_PRACTICE: {
      /* Return args[1] + 1 */
      f->eax = args[1] + 1;
      break;
    }

    case SYS_PT_CREATE: {
      // if (!is_valid_buffer((void*)args[1], 4) ||
      //     !is_valid_buffer((void*)args[2], 4) ||
      //     !is_valid_buffer((void*)args[3], 4)) {
      //   f->eax = TID_ERROR;
      //   break;
      // }
      stub_fun sf = (stub_fun)args[1];
      pthread_fun tf = (pthread_fun)args[2];
      void* arg = (void*)args[3];

      f->eax = pthread_execute(sf, tf, arg);
      break;
    }

    case SYS_PT_EXIT: {
      if (thread_current() == thread_current()->pcb->main_thread) {
        pthread_exit_main();
        break;
      }
      pthread_exit();
      break;
    }

    case SYS_PT_JOIN: {
      f->eax = pthread_join((tid_t)args[1]);
      break;
    }

    case SYS_LOCK_INIT: {
      struct process* pcb = thread_current()->pcb;
      lock_acquire(pcb_lock_ptr);

      /* Too many locks or lock pointer was NULL */
      if (pcb->num_locks == 128 || args[1] == 0) {
        lock_release(pcb_lock_ptr);
        f->eax = false;
        break;
      }

      char* new_lock = (char*)args[1];
      *new_lock = pcb->num_locks;

      pcb->locks[pcb->num_locks] = malloc(sizeof(struct lock));

      if (pcb->locks[pcb->num_locks] == NULL) {
        lock_release(pcb_lock_ptr);
        f->eax = false;
        break;
      }

      lock_init(pcb->locks[pcb->num_locks]);
      pcb->num_locks++;

      lock_release(pcb_lock_ptr);
      f->eax = true;
      break;
    }

    case SYS_LOCK_ACQUIRE: {
      int lock_num = *((char*)args[1]);
      struct process* pcb = thread_current()->pcb;
      lock_acquire(pcb_lock_ptr);

      /* No acquiring locks that haven't been initialized */
      if (pcb->locks[lock_num] == NULL) {
        lock_release(pcb_lock_ptr);
        f->eax = false;
        break;
      }

      /* No double acquires */
      if (pcb->locks[lock_num]->holder == thread_current()) {
        lock_release(pcb_lock_ptr);
        f->eax = false;
        break;
      }
      lock_release(pcb_lock_ptr);

      lock_acquire(pcb->locks[lock_num]);
      f->eax = true;
      break;
    }

    case SYS_LOCK_RELEASE: {
      int lock_num = *((char*)args[1]);
      struct process* pcb = thread_current()->pcb;
      lock_acquire(pcb_lock_ptr);

      /* No releasing locks that haven't been initialized */
      if (pcb->locks[lock_num] == NULL) {
        lock_release(pcb_lock_ptr);
        f->eax = false;
        break;
      }

      /* No releasing locks not owned by this thread */
      if (pcb->locks[lock_num]->holder != thread_current()) {
        lock_release(pcb_lock_ptr);
        f->eax = false;
        break;
      }
      lock_release(pcb_lock_ptr);

      lock_release(pcb->locks[lock_num]);
      f->eax = true;
      break;
    }

    case SYS_SEMA_INIT: {
      struct process* pcb = thread_current()->pcb;

      lock_acquire(pcb_lock_ptr);
      /* Too many semas or trying to initialize NULL sema or value was negative */
      if (pcb->num_semas == 128 || args[1] == 0 || (int)args[2] < 0) {
        lock_release(pcb_lock_ptr);
        f->eax = false;
        break;
      }

      char* new_sema = (char*)args[1];
      *new_sema = pcb->num_semas;

      pcb->semaphores[pcb->num_semas] = malloc(sizeof(struct semaphore));

      if (pcb->semaphores[pcb->num_semas] == NULL) {
        lock_release(pcb_lock_ptr);
        f->eax = false;
        break;
      }

      sema_init(pcb->semaphores[pcb->num_semas], args[2]);
      pcb->num_semas++;

      lock_release(pcb_lock_ptr);
      f->eax = true;
      break;
    }

    case SYS_SEMA_DOWN: {
      int sema_num = *((char*)args[1]);
      struct process* pcb = thread_current()->pcb;

      lock_acquire(pcb_lock_ptr);
      if (pcb->semaphores[sema_num] == NULL) {
        lock_release(pcb_lock_ptr);
        f->eax = false;
        break;
      }
      lock_release(pcb_lock_ptr);

      sema_down(pcb->semaphores[sema_num]);
      f->eax = true;
      break;
    }

    case SYS_SEMA_UP: {
      int sema_num = *((char*)args[1]);
      struct process* pcb = thread_current()->pcb;

      lock_acquire(pcb_lock_ptr);
      if (pcb->semaphores[sema_num] == NULL) {
        lock_release(pcb_lock_ptr);
        f->eax = false;
        break;
      }
      lock_release(pcb_lock_ptr);

      sema_up(pcb->semaphores[sema_num]);
      f->eax = true;
      break;
    }

    case SYS_GET_TID: {
      f->eax = thread_current()->tid;
      break;
    }

    default: { PANIC("Syscall is not implemented"); }
  }

  // lock_release(pcb_lock_ptr);
}
