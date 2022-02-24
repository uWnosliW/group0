#ifndef THREADS_SYNCH_H
#define THREADS_SYNCH_H

#include <list.h>
#include <stdbool.h>

/* A counting semaphore. */
struct semaphore {
  unsigned value;      /* Current value. */
  struct list waiters; /* List of waiting threads. */
};

void sema_init(struct semaphore*, unsigned value);
void sema_down(struct semaphore*);
bool sema_try_down(struct semaphore*);
void sema_up(struct semaphore*);
void sema_self_test(void);

/* Lock. */
struct lock {
  struct thread* holder;      /* Thread holding lock (for debugging). */
  struct semaphore semaphore; /* Binary semaphore controlling access. */
};
typedef struct lock lock_t;

void lock_init(struct lock*);
void lock_acquire(struct lock*);
bool lock_try_acquire(struct lock*);
void lock_release(struct lock*);
bool lock_held_by_current_thread(const struct lock*);

/* Condition variable. */
struct condition {
  struct list waiters; /* List of waiting threads. */
};

void cond_init(struct condition*);
void cond_wait(struct condition*, struct lock*);
void cond_signal(struct condition*, struct lock*);
void cond_broadcast(struct condition*, struct lock*);

/* Readers-writers lock. */
#define RW_READER 1
#define RW_WRITER 0

struct rw_lock {
  struct lock lock;
  struct condition read, write;
  int AR, WR, AW, WW;
};

void rw_lock_init(struct rw_lock*);
void rw_lock_acquire(struct rw_lock*, bool reader);
void rw_lock_release(struct rw_lock*, bool reader);

/* Optimization barrier.

   The compiler will not reorder operations across an
   optimization barrier.  See "Optimization Barriers" in the
   reference guide for more information.*/
#define barrier() asm volatile("" : : : "memory")

// Utility synch objects and ops

/* Atomic counter, for reference counting */
typedef struct atomic_int {
  int val;
  lock_t mutex; // enforce exclusive r&w access to val
} atomic_int_t;

void atomic_int_init(atomic_int_t* ai);
void atomic_int_init_with(atomic_int_t* ai, int val);
void atomic_int_incr(atomic_int_t* ai);
void atomic_int_decr(atomic_int_t* ai);

/* Atomic reference counter */
typedef struct arc {
  void* ptr;
  atomic_int_t ref_ct;
} arc_t;

void arc_init(arc_t* a, void* ptr);
void arc_borrow(arc_t* a);
void arc_drop(arc_t* a, bool free_ptr, bool free_this);

#endif /* threads/synch.h */
