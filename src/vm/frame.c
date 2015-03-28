#include "vm/frame.h"
#include <debug.h>
#include <hash.h>
#include <list.h>
#include <debug.h>
#include <stdio.h>
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "vm/page.h"


/* Clock eviction functions */
static struct frame_table_elem * clock_get_next(void);
static void clock_tick(void);
/* Hash table functions */
static bool hash_less_function(const struct hash_elem *h1, const struct hash_elem *h2, void * aux);
static unsigned hash_hash_function(const struct hash_elem *h, void * aux);
inline static struct frame_table_elem * hash_find_entry(uintptr_t frame_addr);
inline static struct frame_table_elem * hash_delete_entry(uintptr_t frame_addr);


/* Hash table containing a mapping from a physical frame address to the page
   that points to the respective frame.
   NOTE: Keys in this table will ALWAYS be physical pages. Asserts are in place
   to ensure this. */
static struct hash frame_table;


/* Hand for the clock eviction algorithm */
static struct hash_iterator clock_hand;



/* Initialises the frame table by initialising the hash table, as well as the
   frame table lock. */
void
frame_table_init(void)
{
	hash_init(&frame_table, hash_hash_function, hash_less_function, NULL);
	lock_init(&frame_table_lock);
}


/* Searches for an entry in the frame table, given a frame address.
   Returns the list of mapped pages associated with that entry if found,
   NULL otherwise. */
uintptr_t
frame_table_find(uintptr_t frame_addr) {
  
  /* The provided address must not be a kernel address but a physical address */
  ASSERT(! is_kernel_vaddr((void*) frame_addr));

  struct frame_table_elem * elem_in_hash = hash_find_entry(frame_addr);

  /* If the entry was not found */
  if (elem_in_hash == NULL) {
    return 0;
  }

  /* Else, if the entry was found, return it */
  return elem_in_hash->user_address;
}


/* Inserts the given page inside the frame table.
   NOTE: frame_addr represents a physical address. */
void
frame_table_insert(uintptr_t frame_addr, uintptr_t page_addr, uint32_t * pd)
{
  /* The provided address must not be a kernel address but a physical address */
  ASSERT(! is_kernel_vaddr((void*) frame_addr));


  if (hash_find_entry(frame_addr)) {
    frame_table_delete(frame_addr);
  }
//  ASSERT(hash_find_entry(frame_addr) == NULL);

  struct frame_table_elem * new_elem = (struct frame_table_elem *)
      malloc(sizeof(struct frame_table_elem));
  if(!new_elem) {
    PANIC("ERROR: Frame malloc failed!\n");
  }

  new_elem->clock_bit = 1;
  new_elem->frame_addr = frame_addr;
  new_elem->process = thread_current();
  new_elem->user_address = page_addr;
  new_elem->page_dir = pd;

  hash_insert(&frame_table, &new_elem->h_elem);

}


/* Deletes an entry in the frame table.
   CAUTION: This function also deletes all the page structs we allocated as
   part of frame_table_insert() */
void
frame_table_delete(uintptr_t frame_addr)
{
  /* The provided address must not be a kernel address but a physical address */
  ASSERT(! is_kernel_vaddr((void*) frame_addr));

  struct frame_table_elem * elem_to_remove = hash_delete_entry(frame_addr);

  /* The entry to remove was not found in the frame table */
  if (elem_to_remove == NULL) {
    PANIC("The element at %x cannot be deleted from the frame table because "
        "it does not exist\n", frame_addr);
  }

  /* Frees the entry */
  free(elem_to_remove);
}




/* Clock page replacement algorithm. */
struct frame_table_elem *
clock_eviction(void)
{

  hash_first(&clock_hand, &frame_table);
  hash_next(&clock_hand);
  struct frame_table_elem * next_frame =
      hash_entry(hash_cur(&clock_hand), struct frame_table_elem, h_elem);

  return next_frame;

  struct frame_table_elem * victim = NULL;
  int canary = 0;

  /* While we do not find a victim, keep searching */
  while(!victim) {
    clock_tick();
    struct frame_table_elem * frame = clock_get_next();

    if (frame == NULL) {
      if (++canary > 20) {
        PANIC ("The eviction algorithm is broken");
      }
      continue;
    }

    /* If the frame cannot be evicted */
    if(frame->clock_bit) {
      frame->clock_bit = false;
      continue;
    }

    /* A victim was found! */
    victim = frame;
  }

  return victim;
}

/* Returns the next frame pointed by the clock hand. */
static struct frame_table_elem *
clock_get_next(void) {

  if (clock_hand.hash == 0) {
    PANIC("ERROR: Clock hand pointer NULL!\n");
  }

  /* Get the frame from the clock frames list */
  struct frame_table_elem * next_frame =
      hash_entry(hash_cur(&clock_hand), struct frame_table_elem, h_elem);

  return next_frame;
}

/*
 * Moves the hand to the next frame, the clock ticks!
 * Always call this before clock_get_next
 */
static void
clock_tick(void) {

  /* If the pointer is at the end of the list move the hand at the beginning
     else move the hand to the next frame */
  if(clock_hand.hash == 0 || hash_next(&clock_hand) == NULL) {
    hash_first(&clock_hand, &frame_table);
  } else {
    hash_next(&clock_hand);
  }
}


/* Retrieves a frame table element from the frame table.
   Returns this element if found, NULL otherwise. */
inline static struct frame_table_elem *
hash_find_entry(uintptr_t frame_addr)
{
  struct frame_table_elem dummy;
  dummy.frame_addr = frame_addr;

  struct hash_elem * retrieved_ = hash_find(&frame_table, &dummy.h_elem);

  /* If the entry was not found, returns NULL */
  if(retrieved_ == NULL) {
    return NULL;
  }

  struct frame_table_elem * retrieved =
                        hash_entry(retrieved_, struct frame_table_elem, h_elem);

  return retrieved;
}

/* Deletes an entry from the hash table (structure wrapped by the frame table).
   Returns that entry if found, NULL otherwise. */
inline static struct frame_table_elem *
hash_delete_entry(uintptr_t frame_addr)
{
  struct frame_table_elem dummy;
  dummy.frame_addr = frame_addr;

  struct hash_elem * retrieved_ = hash_delete(&frame_table, &dummy.h_elem);

  /* If the entry was not found, returns NULL */
  if(retrieved_ == NULL) {
    return NULL;
  }

  struct frame_table_elem * retrieved =
                        hash_entry(retrieved_, struct frame_table_elem, h_elem);

  return retrieved;
}


/* Returns True is a frame wrapped by h1 precedes a frame wrapped by h2,
   False otherwise. */
static bool
hash_less_function(const struct hash_elem *h1,
                   const struct hash_elem *h2, void * aux UNUSED)
{
  struct frame_table_elem *f1 = hash_entry(h1, struct frame_table_elem, h_elem);
  struct frame_table_elem *f2 = hash_entry(h2, struct frame_table_elem, h_elem);
  return f1->frame_addr - f2->frame_addr;
}

/* Returns a hash value from the given hash element, i.e. a frame address. */
static unsigned
hash_hash_function(const struct hash_elem *h, void * aux UNUSED)
{
  struct frame_table_elem *f1 = hash_entry(h, struct frame_table_elem, h_elem);
  return (unsigned) f1->frame_addr;
}
