#ifndef THREADS_SYNCH_H
#define THREADS_SYNCH_H

#include <list.h>
#include <stdbool.h>

/* A counting semaphore. */
struct semaphore {
  unsigned value;      /* Current value. */
  struct list waiters; /* List of waiting threads. */
};

void sema_init(struct semaphore *, unsigned value);
void sema_down(struct semaphore *);
bool sema_try_down(struct semaphore *);
void sema_up(struct semaphore *);
void sema_self_test(void);

/* Lock. */
struct lock {
  struct list_elem elem;
  struct thread *holder;      /* Thread holding lock (for debugging). */
  struct semaphore semaphore; /* Binary semaphore controlling access. */
};
typedef struct lock lock_t;

void lock_init(struct lock *);
void lock_acquire(struct lock *);
bool lock_try_acquire(struct lock *);
void lock_release(struct lock *);
bool lock_held_by_current_thread(const struct lock *);

/* Condition variable. */
struct condition {
  struct list waiters; /* List of waiting threads. */
};

void cond_init(struct condition *);
void cond_wait(struct condition *, struct lock *);
void cond_signal(struct condition *, struct lock *);
void cond_broadcast(struct condition *, struct lock *);

/* Readers-writers lock. */
#define RW_READER 1
#define RW_WRITER 0

struct rw_lock {
  struct lock lock;
  struct condition read, write;
  int AR, WR, AW, WW;
};

void rw_lock_init(struct rw_lock *);
void rw_lock_acquire(struct rw_lock *, bool reader);
void rw_lock_release(struct rw_lock *, bool reader);

/* Optimization barrier.

   The compiler will not reorder operations across an
   optimization barrier.  See "Optimization Barriers" in the
   reference guide for more information.*/
#define barrier() asm volatile("" : : : "memory")

// Utility synch objects and ops

/* Closure, for capturing environment */
typedef struct closure {
  void *env;
  void *(*cl)(void *, void *); // env, then args
} closure_t;

/* Initialize closure with default vals */
void closure_init(closure_t *cl, void *env, void *(*fn)(void *, void *));

/* Atomic counter, for reference counting */
typedef struct atomic_int {
  int val;
  lock_t mutex; // enforce exclusive r&w access to val
} atomic_int_t;
/* Initialize atomic_int to 0 */
void atomic_int_init(atomic_int_t *ai);
/* Initialize atomic_int with specified value */
void atomic_int_init_with(atomic_int_t *ai, int val);
/* Increment atomically */
void atomic_int_incr(atomic_int_t *ai);
/* Decrement atomically */
void atomic_int_decr(atomic_int_t *ai);
/* Update integer atomically. `fn` must be a pure function. */
void atomic_int_call(atomic_int_t *ai, int (*fn)(int));
/* Update integer atomically, using closure. `cl` must be a pure closure that maps int to int. */
void atomic_int_call_cl(atomic_int_t *ai, closure_t *cl);

#define atomic_int_call_macro(AI, STATEMENTS)                                                      \
  {                                                                                                \
    lock_acquire(&(AI)->mutex);                                                                    \
    {STATEMENTS} lock_release(&(AI)->mutex);                                                       \
  }

/* ARC_OBJECT is pointer to object containing an atomic_int with member name `arc` */
#define arc_extract_atomic_int(ARC_OBJ) ((atomic_int_t *)(&(ARC_OBJ)->arc))
#define arc_init(ARC_OBJ) (atomic_int_init(arc_extract_atomic_int(ARC_OBJ)))
#define arc_init_with(ARC_OBJ, VAL) (atomic_int_init_with(arc_extract_atomic_int(ARC_OBJ), VAL))
#define arc_incr(ARC_OBJ) (atomic_int_incr(arc_extract_atomic_int(ARC_OBJ)))
#define arc_decr(ARC_OBJ) (atomic_int_decr(arc_extract_atomic_int(ARC_OBJ)))

#define arc_drop_call_cl(ARC_OBJ, ON_DROP_CL)                                                      \
  {                                                                                                \
    atomic_int_t *ai = arc_extract_atomic_int(ARC_OBJ);                                            \
    lock_acquire(&ai->mutex);                                                                      \
    if (--ai->val == 0) {                                                                          \
      closure_t *cl = (ON_DROP_CL);                                                                \
      if (cl != NULL) {                                                                            \
        cl->cl(cl->env, NULL);                                                                     \
      }                                                                                            \
      free((ARC_OBJ));                                                                             \
    } else {                                                                                       \
      lock_release(&ai->mutex);                                                                    \
    }                                                                                              \
  }

#endif /* threads/synch.h */
