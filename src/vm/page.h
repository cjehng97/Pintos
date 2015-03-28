#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <list.h>
#include <hash.h>
#include "threads/synch.h"

enum page_situation {
  IS_ZERO,                        /* The page is zeroed */
  IN_SWAP,                        /* The page is swapped */
  NOT_LOADED,                     /* The page is not loaded (lazy loading) */
  IN_MEMORY                       /* The page is in memory */
};

struct supplementary_page_entry
{
  void * virtual_address;         /* Pointer to the page address */
  enum page_situation page_sit;   /* Page situation */
  struct hash_elem h_elem;        /* Hash element for the hash table */
};


/* Supplementary page table functions */
void supplementary_init(struct hash * hash);
void supplementary_insert(struct hash * hash, void * vaddr, enum page_situation page_sit);
void supplementary_delete(struct hash * hash, void * vaddr);
struct supplementary_page_entry * supplementary_find (struct hash * hash, void * vaddr);
void supplementary_table_destroy(struct hash * hash);


#endif /* VM_PAGE_H */
