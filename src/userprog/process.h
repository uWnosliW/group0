#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <list.h>
#include <stdint.h>
#include "filesys/file.h"
#include "threads/thread.h"

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

bool is_valid_buffer(void* ptr, size_t deref_size);

bool is_valid_string(char* ptr);

struct fd_table_entry* get_fd_table_entry(uint32_t fd);

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  uint32_t* pagedir;             /* Page directory. */
  char process_name[16];         /* Name of the main thread */
  struct thread* main_thread;    /* Pointer to main thread */
  struct process_status* status; /* Status of the current thread */
  struct list child_processes;   /* List of process_status's of the children processes */
  struct list fd_table;          /* List of fd_table_entry_ts, relevant in File syscalls */
  struct file* executable;
};

/* Information about the thread to be started */
struct start_thread_arg {
  char* file_name;               /* Name of the executable */
  struct process_status* status; /* The status of the thread */
};

/* Information about the shared status of parent and child processes */
struct process_status {
  struct list_elem elem;    /* To put this in a list */
  int exit_code;            /* Exit code set once thread terminates */
  struct semaphore is_dead; /* >0 if thread is dead, 0 if alive */
  bool success;             /* True if the program loaded successfully */
  pid_t pid;                /* PID of this process */
  lock_t lock;              /* Locks ref_count when it's being updated */
  int ref_count; /* Counter of how many threads currently point to this struct, can be freed once ref_count is 0 */
};

/* A file descriptor table entry */
struct fd_table_entry {
  struct list_elem elem; /* To put this in a list */
  uint32_t fd;           /* Unique file descriptor id */
  struct file* file;     /* The file referenced by this file descriptor */
};

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif /* userprog/process.h */
