#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "filesys/file.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include <list.h>
#include <stdint.h>

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
  struct lock pcb_lock; /* Lock for serializing pcb operations */

  uint32_t* pagedir;             /* Page directory. */
  char process_name[16];         /* Name of the main thread */
  struct thread* main_thread;    /* Pointer to main thread */
  struct process_status* status; /* Status of the current thread */
  struct list child_processes;   /* List of process_status's of the children processes */
  struct list fd_table;          /* List of fd_table_entry_ts, relevant in file syscalls */

  int num_locks;                     /* Number of locks this process has created */
  int num_semas;                     /* Number of semaphores this process has created */
  struct lock* locks[128];           /* List of pointers to user locks */
  struct semaphore* semaphores[128]; /* List of pointers to user semaphores */

  // BEGIN USER THREADS //
  struct list pthread_statuses;
  struct list current_threads;
  bool is_dying;
  // END USER THREADS //

  struct file* executable;
};

// BEGIN USER THREADS //
struct pthread_status {
  struct list_elem elem;
  tid_t tid;
  bool joined;
  struct semaphore finished; /* Used once when setting up the thread, again while joining */
  atomic_int_t arc;
};

struct start_pthread_arg {
  struct process* pcb;
  stub_fun sf;
  pthread_fun tf;
  void* tf_arg;
  struct pthread_status* status;
};
// END USER THREADS //

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
  atomic_int_t arc;
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
