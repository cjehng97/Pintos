#include "vm/swap.h"
#include <bitmap.h>
#include "devices/block.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/frame.h"

#define SECTORS_PER_PAGE (PGSIZE/BLOCK_SECTOR_SIZE)

/* The swap bitmap tracks in-use and free swap slots. It allows picking an
   unused swap slot for evicting a page from its frame to the swap partition.
   Finally, the swap table also allows freeing a swap slot when its page is
   read back or the process whose page was swapped is terminated */
static struct bitmap * swap_bitmap;

/* Swap table block */
static struct block * swap_block;

/* Size of the swap table block */
static unsigned swap_block_size;


static void swap_bitmap_init(void);
static bool hash_less_function(const struct hash_elem *h1,
    const struct hash_elem *h2, void * aux);
static unsigned hash_hash_function(const struct hash_elem *h, void * aux);

inline static struct swap_table_elem *
hash_find_entry(struct hash * h, uintptr_t user_virtual_address);
inline static struct swap_table_elem *
hash_delete_entry(struct hash * h, uintptr_t user_virtual_address);



/*
 * The most important bit of this file. Performs the swapping algorithm.
 */
void
swap_make_space(void) {

  lock_acquire(&frame_table_lock);

  // Clock Eviction
  struct frame_table_elem * frame_to_be_evicted = clock_eviction();

  // Do this copies because frame_table_delete will mess it
  struct thread * owner_of_frame = frame_to_be_evicted->process;
  uintptr_t user_address = frame_to_be_evicted->user_address;
  uintptr_t frame_addr = frame_to_be_evicted->frame_addr;
  uint32_t * page_dir = frame_to_be_evicted->page_dir;

  lock_acquire(&owner_of_frame->spt_lock);

  // Delete page from the Page Table
  release_page(frame_to_be_evicted->page_dir,
      frame_to_be_evicted->user_address);

  // Delete Frame from the Frame Table
  frame_table_delete(frame_to_be_evicted->frame_addr);

  lock_release(&frame_table_lock);

  // Set the swap_bitmap and copy into swap
  size_t swap_start_index = swap_write(ptov(frame_addr));

  // Insert into the swap table
  swap_table_insert(&owner_of_frame->swap_table, user_address,
      swap_start_index);

  // Insert into the supplementary page table
  supplementary_insert(&owner_of_frame->supplementary_page_table, user_address,
      IN_SWAP);

  lock_release(&owner_of_frame->spt_lock);

  // Insert the frame back into the frame pool
  palloc_free_page(ptov(frame_addr));

}


void
swap_put_back(uintptr_t uaddr) {

  // Round frames down. We can only find frames if they are multiples of 2^12
  if (uaddr && PGMASK) {
    uaddr &= NPGMASK;
  }

  // Check swap table
  uintptr_t swap_index = swap_table_find(&thread_current()->swap_table, uaddr);
  if (swap_index == BITMAP_ERROR) {
    PANIC("The frame requested could not be found in the swap table");
  }

  // Request new frame
  void * new_frame = palloc_get_page(0);

  // Read from swap and clear bitmap
  swap_read(swap_index, new_frame);

  swap_table_delete(&thread_current()->swap_table, uaddr);

  lock_acquire(&thread_current()->spt_lock);
  supplementary_delete(&thread_current()->supplementary_page_table, uaddr);
  lock_release(&thread_current()->spt_lock);

  // PT and frame table insert
  install_page(uaddr, new_frame, true);

}


/* Initialises the swap table by getting the swap block and creating the swap
   table of the size of the swap block. */
void
swap_init(void)
{
  swap_bitmap_init();
  lock_init(&swap_lock);
}


/* Reads a swap slot, i.e. loads a page from the swap disk to the memory at the
   given address: dest_addr.
   NOTE: swap_free() should ALWAYS be called after having called swap_read()! */
void
swap_read(size_t swap_index, void * dest_addr)
{
  /* Ensures that the swap_index is valid, and that the page is swapped */
  ASSERT(swap_index < swap_block_size);
  ASSERT(bitmap_test(swap_bitmap, swap_index));

  size_t i;

  /* Iterates through all the sectors that need to be read for the page
     to be loaded into memory */
  for (i = 0; i < SECTORS_PER_PAGE; i++) {
    block_read(swap_block, swap_index + i, dest_addr + (i * BLOCK_SECTOR_SIZE));
  }

  /* The page previously at swap_index is not in the swap_table anymore */
  bitmap_set_multiple(swap_bitmap, swap_index, SECTORS_PER_PAGE, false);
}

/* Write into a swap slot, i.e. loads a page from the memory to the swap disk
   from the given address: origin_addr.
   Returns the swap index of the newly swapped page. */
size_t
swap_write(void * origin_addr)
{
  /* Finds the first group of SECTORS_PER_PAGE consecutive bits in the
     swap_table that are all set to False, flips them all to True,
     and returns the index of the first bit in the group. */
  size_t swap_index = bitmap_scan_and_flip(swap_bitmap, 0, SECTORS_PER_PAGE,
      false);

  if (swap_index == BITMAP_ERROR) {
    PANIC("ERROR: No more swap space, write to swap disk failed!");
  }

  size_t i;

  /* Iterates through all the sectors that need to be written for thepage
     to be swapped */
  for (i = 0; i < SECTORS_PER_PAGE; i++) {
    
    /* Ensures that the swap_index is valid,
       and that no page is already swapped in this slot */
    ASSERT(swap_index + i < swap_block_size);
    ASSERT(bitmap_test(swap_bitmap, swap_index + i));

    block_write(swap_block, swap_index + i,
        origin_addr + (i * BLOCK_SECTOR_SIZE));
  }

  return swap_index;
}


/*
 * Inserts into the swap table
 * key: User Virtual Page address
 * value: the index of the swap
 */
void
swap_table_insert(struct hash * h, uintptr_t user_virtual_address, uintptr_t swap_index)
{

  ASSERT(is_user_vaddr ((void*) user_virtual_address));

  struct swap_table_elem * new_elem = (struct swap_table_elem *)
      malloc(sizeof(struct swap_table_elem));
  if(!new_elem) {
    PANIC("ERROR: Swap table malloc failed!\n");
  }

  new_elem->user_virtual_address = user_virtual_address;
  new_elem->swap_index = swap_index;

  hash_insert(h, &new_elem->h_elem);
}

/*
 * Delets from the Swap Table
 */
void
swap_table_delete(struct hash * h, uintptr_t user_virtual_address)
{

  ASSERT(is_user_vaddr ((void*) user_virtual_address));

  struct swap_table_elem * elem_to_remove =
      hash_delete_entry(h, user_virtual_address);

  /* The entry to remove was not found in the frame table */
  if (elem_to_remove == NULL) {
    PANIC("The element at %x cannot be deleted from the frame table because "
        "it does not exist\n", user_virtual_address);
  }

  /* Frees the entry */
  free(elem_to_remove);

}

/*
 * Finds in the Swap Table
 */
uintptr_t
swap_table_find(struct hash * h, uintptr_t user_virtual_address)
{

  ASSERT(is_user_vaddr ((void*) user_virtual_address));

  struct swap_table_elem * elem_to_find =
      hash_find_entry(h, user_virtual_address);

  /* The entry to remove was not found in the frame table */
  if (elem_to_find == NULL) {
    return BITMAP_ERROR;
  }

  return elem_to_find->swap_index;
}


static void
swap_bitmap_init(void) {
  swap_block = block_get_role(BLOCK_SWAP);

  /* If the swap block allocation failed */
  if (!swap_block) {
    PANIC("ERROR: Swap block allocation failed!");
  }

  // This is going to be 8192 for most of the tests
  swap_block_size = block_size(swap_block);

  swap_bitmap = bitmap_create(swap_block_size);

  /* If the swap table initialisation failed */
  if (!swap_bitmap) {
    PANIC("ERROR: Swap bitmap initialisation failed!");
  }
}





/* Retrieves a frame table element from the frame table.
   Returns this element if found, NULL otherwise. */
inline static struct swap_table_elem *
hash_find_entry(struct hash * h, uintptr_t user_virtual_address)
{
  struct swap_table_elem dummy;
  dummy.user_virtual_address = user_virtual_address;

  struct hash_elem * retrieved_ = hash_find(h, &dummy.h_elem);

  /* If the entry was not found, returns NULL */
  if (retrieved_ == NULL) {
    return NULL;
  }

  struct swap_table_elem * retrieved =
      hash_entry(retrieved_, struct swap_table_elem, h_elem);

  return retrieved;
}

/* Deletes an entry from the hash table (structure wrapped by the frame table).
   Returns that entry if found, NULL otherwise. */
inline static struct swap_table_elem *
hash_delete_entry(struct hash * h, uintptr_t user_virtual_address)
{
  struct swap_table_elem dummy;
  dummy.user_virtual_address = user_virtual_address;

  struct hash_elem * retrieved_ = hash_delete(h, &dummy.h_elem);

  /* If the entry was not found, returns NULL */
  if (retrieved_ == NULL) {
    return NULL;
  }

  struct swap_table_elem * retrieved =
      hash_entry(retrieved_, struct swap_table_elem, h_elem);

  return retrieved;
}



void
swap_table_init(struct hash * h) {
  hash_init(h, hash_hash_function, hash_less_function, NULL);
}

/* Returns True is a frame wrapped by h1 precedes a frame wrapped by h2,
   False otherwise. */
static bool
hash_less_function(const struct hash_elem *h1,
                   const struct hash_elem *h2, void * aux UNUSED)
{
  struct swap_table_elem *f1 = hash_entry(h1, struct swap_table_elem, h_elem);
  struct swap_table_elem *f2 = hash_entry(h2, struct swap_table_elem, h_elem);
  return f1->user_virtual_address - f2->user_virtual_address;
}

/* Returns a hash value from the given hash element, i.e. a frame address. */
static unsigned
hash_hash_function(const struct hash_elem *h, void * aux UNUSED)
{
  struct swap_table_elem *f1 = hash_entry(h, struct swap_table_elem, h_elem);
  return (unsigned) f1->user_virtual_address;
}
