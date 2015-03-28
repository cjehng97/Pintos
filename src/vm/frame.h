#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "vm/page.h"
#include <hash.h>
#include <stdint.h>
#include "threads/palloc.h"
#include "threads/synch.h"

struct frame_table_elem {
  // Key
  uintptr_t frame_addr;    /* Frame address */

  // Values
  uintptr_t user_address;  /* User virtual address */
  uint32_t * page_dir;     /* Page directory */
  struct thread * process; /* Pointer to the thread owning the frame */

  // Frame eviction algorithm
  bool clock_bit;          /* False: the frame can be evicted, True otherwise */

  // Book-keeping
  struct hash_elem h_elem; /* Hash element for the frame table */
};

/* Frame table functions */
void frame_table_init(void);
void frame_table_insert(uintptr_t frame_addr, uintptr_t page_addr, uint32_t * pd);
void frame_table_delete(uintptr_t frame_addr);
uintptr_t frame_table_find(uintptr_t frame_addr);

/* Clock Eviction Algorithm */
struct frame_table_elem * clock_eviction(void);

/* External lock for the frame table. Not to be used inside the functions */
struct lock frame_table_lock;

#endif /* VM_FRAME_H */
