#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "filesys/directory.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"

static struct semaphore temporary;
static thread_func start_process NO_RETURN;
static bool load(const char* file_name, void (**eip)(void), void** esp);

/* is_valid_buffer - Returns whether the first size bytes of the buffer pointed to by ptr are in user space and mapped. */
bool is_valid_buffer(void* ptr, size_t size) {
  /* NULL is an invalid buffer */
  if (ptr == NULL) {
    return false;
  }

  /* If the first byte of ptr does not lie in user space or the address pointed to is unmapped, return false */
  if (!is_user_vaddr(ptr) || pagedir_get_page(thread_current()->pcb->pagedir, ptr) == NULL) {
    return false;
  }

  /* If the last byte of ptr does not lie in user space or the address pointed to is unmapped, return false */
  if (!is_user_vaddr((void*)((char*)ptr + size)) ||
      pagedir_get_page(thread_current()->pcb->pagedir, (void*)((char*)ptr + size)) == NULL) {
    return false;
  }

  /* If we got here the first size bytes were valid */
  return true;
}

/* is_valid_string - Returns whether the entirety of the string the char* passed in points to is in user space and mapped. */
bool is_valid_string(char* ptr) {
  /* Initial check to make sure ptr is not null, a valid user address, and mapped to a valid page */
  if (ptr == NULL || !is_user_vaddr(ptr) ||
      pagedir_get_page(thread_current()->pcb->pagedir, ptr) == NULL) {
    return false;
  }

  /* Repeat the checks from before byte by byte until a null byte is reached */
  char c = *ptr;
  while (c != '\0') {
    c = *ptr++;

    /* If ptr is not a valid user address or is unmapped, return false */
    if (!is_user_vaddr(ptr) || pagedir_get_page(thread_current()->pcb->pagedir, ptr) == NULL) {
      return false;
    }
  }

  /* If we get here all bytes were valid */
  return true;
}

/* get_fd_table_entry - Returns the file descriptor matching the id passed in. If no match is found returns NULL. */
struct fd_table_entry* get_fd_table_entry(uint32_t fd) {
  struct list* fd_table_ptr = &thread_current()->pcb->fd_table;
  struct fd_table_entry* curr_fd;

  /* Iterate through the file descriptor table in the current thread */
  struct list_elem* curr = list_begin(fd_table_ptr);
  while (curr != list_end(fd_table_ptr)) {
    curr_fd = list_entry(curr, struct fd_table_entry, elem);

    /* If a match is found, break */
    if (curr_fd->fd == fd) {
      break;
    }

    curr = list_next(curr);
  }

  /* If we reached the end no matches were found, return NULL, else return the matched file descriptor */
  if (curr == list_end(fd_table_ptr)) {
    return NULL;
  } else {
    return curr_fd;
  }
}

/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;

  /* Allocate process control block
     It is important that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  success = t->pcb != NULL;

  /* Kill the kernel if we did not succeed */
  ASSERT(success);

  /* Initialize child process list and file descriptor table in the PCB */
  list_init(&t->pcb->child_processes);
  list_init(&t->pcb->fd_table);
}

/* Starts a new thread running a user program loaded from
   FILENAME. The new thread may be scheduled (and may even exit)
   before process_execute() returns. Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* file_name) {
  char* fn_copy;
  tid_t tid;

  /* Initialize the child's process_status, erroring if malloc fails */
  struct process_status* child_status = malloc(sizeof(struct process_status));
  if (child_status == NULL) {
    return TID_ERROR;
  }
  list_push_back(&thread_current()->pcb->child_processes, &child_status->elem);
  child_status->exit_code = 0;
  sema_init(&child_status->is_dead, 0);
  child_status->success = false;
  lock_init(&child_status->lock);
  child_status->ref_count = 2;

  /* Initialize semaphore to wait on the child process */
  sema_init(&temporary, 0);

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  /* Initialize the child arguments passed into start_process, erroring if malloc fails */
  struct start_thread_arg* child_args = malloc(sizeof(struct start_thread_arg));
  if (child_args == NULL) {
    return TID_ERROR;
    free(child_status);
  }
  child_args->file_name = fn_copy;
  child_args->status = child_status;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(file_name, PRI_DEFAULT, start_process, child_args);
  sema_down(&child_status->is_dead);
  free(child_args);

  /* If child fails to load, free shared data. Everything else
     is freed in start_process when it fails to load */
  if (!child_status->success) {
    list_remove(&child_status->elem);
    free(child_status);
    return TID_ERROR;
  }

  /* Free the copy of FILE_NAME if thread creation failed */
  if (tid == TID_ERROR)
    palloc_free_page(fn_copy);

  return tid;
}

/* A thread function that loads a user process and starts it running. */
static void start_process(void* args_) {
  /* Cast generic pointer passed in and get the arguments passed in*/
  struct start_thread_arg* args = (struct start_thread_arg*)args_;
  char* file_name = args->file_name;
  struct process_status* status = args->status;

  struct thread* t = thread_current();
  struct intr_frame if_;
  bool success, pcb_success;

  /* Set pid of child thread to that of the current thread */
  status->pid = t->tid;

  /* Allocate process control block */
  struct process* new_pcb = malloc(sizeof(struct process));
  success = pcb_success = new_pcb != NULL;

  /* Initialize process control block */
  if (success) {
    /* Ensure that timer_interrupt() -> schedule() -> process_activate()
       does not try to activate our uninitialized pagedir */
    new_pcb->pagedir = NULL;
    t->pcb = new_pcb;

    /* Make child point to its status */
    t->pcb->status = status;

    /* Continue initializing the PCB as normal */
    t->pcb->main_thread = t;
    strlcpy(t->pcb->process_name, t->name, sizeof t->name);

    /* Initialize the PCB's child process list and file descriptor table */
    list_init(&t->pcb->child_processes);
    list_init(&t->pcb->fd_table);
  }

  /* Initialize interrupt frame and load executable. */
  if (success) {
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    success = load(file_name, &if_.eip, &if_.esp);

    /* Initialize FPU for intr_frame */
    uint8_t tmp[108];
    asm volatile("fsave (%0)" : : "g"(&tmp));     /* Save parent thread's FPU */
    asm volatile("fninit");                       /* Initialize FPU for child thread */
    asm volatile("fsave (%0)" : : "g"(&if_.fpu)); /* Save newly initialized FPU for child thread */
    asm volatile("frstor (%0)" : : "g"(&tmp)); /* Restore parent thread's FPU to continue routine */
  }

  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    /* Avoid race where PCB is freed before t->pcb is set to NULL
       If this happens, then an unfortuantely timed timer interrupt
       can try to activate the pagedir, but it is now freed memory */
    struct process* pcb_to_free = t->pcb;
    sema_up(&(t->pcb->status->is_dead));
    t->pcb = NULL;
    free(pcb_to_free);
  }

  /* Clean up. Exit on failure or jump to userspace */
  palloc_free_page(file_name);
  if (!success) {
    sema_up(&temporary);
    thread_exit();
  } else {
    t->pcb->status->success = true;
  }
  sema_up(&t->pcb->status->is_dead);

  /* Initialize FPU */
  asm volatile("fninit");

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t pid) {
  /* Find the child process in child_processes, removing it if found to prevent double waits */
  struct list* child_processes_ptr = &thread_current()->pcb->child_processes;
  struct process_status* child_process_status;

  struct list_elem* curr = list_begin(child_processes_ptr);
  while (curr != list_end(child_processes_ptr)) {
    child_process_status = list_entry(curr, struct process_status, elem);
    if (child_process_status->pid == pid) {
      list_remove(&child_process_status->elem);
      break;
    }
    curr = list_next(curr);
  }

  /* If we didn't find the matching child, return -1.
     The process with the pid passed in is not a direct child, or we already called wait on it. */
  if (curr == list_end(child_processes_ptr)) {
    return -1;
  }

  /* Wait for the child process to finish executing */
  sema_down(&child_process_status->is_dead);

  /* Decrement ref_count and free child status if ref_count reaches 0.
     Return the child process' exit code. */
  lock_acquire(&child_process_status->lock);
  int exit_code = child_process_status->exit_code;

  child_process_status->ref_count -= 1;
  if (child_process_status->ref_count == 0) {
    free(child_process_status);
  } else {
    lock_release(&child_process_status->lock);
  }

  return exit_code;
}

/* Free the current process's resources. */
void process_exit(void) {
  struct thread* curr_thread = thread_current();
  uint32_t* pd;

  /* If this thread does not have a PCB, exit immediately */
  if (curr_thread->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = curr_thread->pcb->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
       curr_thread->pcb->pagedir to NULL before switching page directories,
       so that a timer interrupt can't switch back to the
       process page directory.  We must activate the base page
       directory before destroying the process's page
       directory, or our active page directory will be one
       that's been freed (and cleared). */
    curr_thread->pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  /* Decrement ref count in shared status.
    If ref_count reaches 0, free shared status */
  struct process_status* status = curr_thread->pcb->status;

  lock_acquire(&status->lock);
  status->ref_count -= 1;
  if (status->ref_count <= 0) {
    free(status);
  } else {
    lock_release(&status->lock);
  }

  /* Clean up child process list */
  struct list* child_processes_ptr = &curr_thread->pcb->child_processes;
  struct process_status* child_process_status;

  struct list_elem* curr = list_begin(child_processes_ptr);
  while (curr != list_end(child_processes_ptr)) {
    child_process_status = list_entry(curr, struct process_status, elem);

    /* Move to next before freeing child_process_status to prevent next from being set to the wrong address */
    curr = list_next(curr);

    /* Decrement reference count in each shared status. Free if ref_count reaches 0. */
    lock_acquire(&child_process_status->lock);
    child_process_status->ref_count -= 1;
    if (child_process_status->ref_count <= 0) {
      list_remove(&child_process_status->elem);
      free(child_process_status);
    } else {
      lock_release(&child_process_status->lock);
    }
  }

  /* Clean up file descriptor table */
  struct list* fd_table_ptr = &curr_thread->pcb->fd_table;
  struct fd_table_entry* fdt_entry;

  curr = list_begin(fd_table_ptr);
  while (curr != list_end(fd_table_ptr)) {
    fdt_entry = list_entry(curr, struct fd_table_entry, elem);

    /* Move to next before freeing child_process_status to prevent next from being set to the wrong address */
    curr = list_next(curr);

    /* Free the file descriptor and remove it from the file descriptor table */
    list_remove(&fdt_entry->elem);
    file_close(fdt_entry->file);
    free(fdt_entry);
  }

  /* Mark the child thread as dead */
  sema_up(&status->is_dead);

  /* Close the now-stopped executable and allow writing to it */
  file_close(curr_thread->pcb->executable);

  /* Free the PCB of this process and kill this thread
     Avoid race where PCB is freed before t->pcb is set to NULL
     If this happens, then an unfortuantely timed timer interrupt
     can try to activate the pagedir, but it is now freed memory */
  curr_thread->pcb = NULL;
  free(curr_thread->pcb);

  sema_up(&temporary);
  thread_exit();
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, void (**eip)(void), void** esp) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  int argc = 0;
  const char* argv[128];
  void* argv_addr[128];

  char* save_ptr;
  char* token = strtok_r((char*)file_name, " ", &save_ptr);
  while (token != NULL) {
    argv[argc] = token;
    argc += 1;
    token = strtok_r(NULL, " ", &save_ptr);
  }

  strlcpy(t->pcb->process_name, argv[0], PGSIZE);

  /* Open executable file. */
  file = filesys_open(argv[0]);
  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }
  t->pcb->executable = file;

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  *esp = (void (*)(void))PHYS_BASE;
  for (int i = argc - 1; i >= 0; i--) {
    // we add 1 b/c of null terminator
    *esp -= strlen(argv[i]) + 1;
    argv_addr[i] = *esp;
    strlcpy(*esp, argv[i], PGSIZE);
  }

  /* Word alignment */
  int lower_bytes_pad = ((3 + argc) * 4) % 16;
  int upper_bytes_pad = (-1 * (int)(*esp)) % 16;
  int padding_needed = (-1 * (upper_bytes_pad + lower_bytes_pad)) % 16;
  if (padding_needed < 0) {
    padding_needed += 16;
  }

  /* Inserting padding for arguments */
  *esp -= padding_needed;
  memset(*esp, 0, padding_needed);

  /* Null terminator sentinel */
  *esp -= sizeof(*esp);
  memset(*esp, 0, sizeof(int));

  /* Push addresses of argv[argc] */
  for (int i = argc - 1; i >= 0; i--) {
    *esp -= sizeof(*esp);
    memcpy(*esp, &argv_addr[i], sizeof(int));
  }

  /* Push address of argv */
  void* address_of_argv = *esp;
  *esp -= sizeof(*esp);
  memcpy(*esp, &address_of_argv, sizeof(int));

  /* Push argc */
  *esp -= sizeof(*esp);
  memcpy(*esp, &argc, sizeof(int));

  /* Push fake address */
  *esp -= sizeof(*esp);

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:

  // prevent any writes to this executable
  if (success) {
    file_deny_write(file);
  }
  /* We arrive here whether the load is successful or not. */
  // file_close(file);
  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      palloc_free_page(kpage);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }
