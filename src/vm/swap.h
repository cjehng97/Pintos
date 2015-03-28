#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <hash.h>
#include <stdint.h>
#include "threads/synch.h"

struct swap_table_elem {
  uintptr_t user_virtual_address;  /* User virtual address */
  uintptr_t swap_index;            /* Index at which the start of the data
                                      swapped in the swap partition lies */
  struct hash_elem h_elem;         /* Hash element used by the swap table */
};

struct lock swap_lock;             /* Swap lock */

void swap_make_space(void);
void swap_put_back(uintptr_t uaddr);

void swap_init(void);
void swap_table_init(struct hash * hash);

void swap_read(size_t swap_index, void * dest_addr);
size_t swap_write(void * origin_addr);

void swap_table_insert(struct hash * h, uintptr_t vaddr, uintptr_t swap_index);
void swap_table_delete(struct hash * h, uintptr_t vaddr);
uintptr_t swap_table_find(struct hash * h, uintptr_t vaddr);

#endif /* VM_SWAP_H */
