#include "vm/page.h"
#include <hash.h>
#include <debug.h>
#include "threads/malloc.h"
#include "threads/pte.h"

/* Hash table functions */
static bool hash_less_function(const struct hash_elem *h1, const struct hash_elem *h2, void * aux);
static unsigned hash_hash_function(const struct hash_elem *h, void * aux);
static void hash_hash_action_func (struct hash_elem *e, void *aux);

/* Supplementary page table functions */
inline static struct supplementary_page_entry *
hash_find_entry(struct hash * hash, void * virtual_address);
inline static struct supplementary_page_entry *
hash_delete_entry(struct hash * hash, void * virtual_address);


/* Initialises the supplementary page table by initialising the hash table. */
void
supplementary_init(struct hash * hash)
{
  hash_init(hash, hash_hash_function, hash_less_function, NULL);
}


/* Inserts the given page inside the supplementary page table. */
void
supplementary_insert(struct hash * hash,
                     void * vaddr, enum page_situation page_sit)
{
  /* Creates a new page */
  struct supplementary_page_entry * new_entry =
      (struct supplementary_page_entry *)
      malloc(sizeof(struct supplementary_page_entry));

  /* If memory allocation failed */
  if(!new_entry) {
    PANIC("ERROR: Page structure allocation failed!\n");
  }

  /* Sets up the page fields */
  new_entry->page_sit = page_sit;
  new_entry->virtual_address = start_of_page(vaddr);

  /* Inserts the page inside the supplementary page table */
  hash_insert(hash, &new_entry->h_elem);
}

void supplementary_delete(struct hash * hash, void * vaddr) {

  ASSERT (is_user_vaddr(vaddr));

  struct supplementary_page_entry * elem_to_remove = hash_delete_entry(hash, vaddr);

  if (elem_to_remove == NULL) {
    PANIC("The element at %x cannot be deleted from the SPT table because "
        "it does not exist\n", vaddr);
  }

  free(elem_to_remove);
}


/* Retrieves a page table entry from the supplementary page table.
   Returns this element if found, NULL otherwise. */
struct supplementary_page_entry *
supplementary_find (struct hash * hash, void * vaddr)
{
	return hash_find_entry(hash, start_of_page(vaddr));
}


void
supplementary_table_destroy(struct hash * hash) {
	hash_destroy(hash, hash_hash_action_func);
}





/* This is a dummy function, the supplementary page table does not need to do any clean up,
 * the other page tables handle their resources */
static void hash_hash_action_func (struct hash_elem *e, void *aux) {

}

/* Returns True if a page wrapped by h1 precedes another page wrapped h2,
   False otherwise. */
static bool
hash_less_function(const struct hash_elem *h1, const struct hash_elem *h2, void * aux UNUSED)
{
  struct supplementary_page_entry *f1 = hash_entry(h1, struct supplementary_page_entry, h_elem);
  struct supplementary_page_entry *f2 = hash_entry(h2, struct supplementary_page_entry, h_elem);
  return f1->virtual_address - f2->virtual_address;
}


/* Returns a hash value from the given hash element, i.e. a page address. */
static unsigned
hash_hash_function(const struct hash_elem *h, void * aux UNUSED)
{
  struct supplementary_page_entry *f1 = hash_entry(h, struct supplementary_page_entry, h_elem);
  return (unsigned) start_of_page(f1->virtual_address);
}


/* Retrieves a supplementary page table element from the supplementary page
   table. Returns this element if found, NULL otherwise. */
inline static struct supplementary_page_entry *
hash_find_entry(struct hash * hash, void * virtual_address)
{
  struct supplementary_page_entry dummy;

  /* The key corresponds to the page itself, remove the page offset */
  dummy.virtual_address = start_of_page(virtual_address);

  struct hash_elem * retrieved_ = hash_find(hash, &dummy.h_elem);

  /* If the entry was not found, returns NULL */
  if(retrieved_ == NULL) {
    return NULL;
  }

  struct supplementary_page_entry * retrieved = 
                hash_entry(retrieved_, struct supplementary_page_entry, h_elem);

  return retrieved;
}


/* Deletes an entry from the hash table (structure wrapped by the frame table).
   Returns that entry if found, NULL otherwise. */
inline static struct supplementary_page_entry *
hash_delete_entry(struct hash * hash, void * virtual_address)
{
  struct supplementary_page_entry dummy;
  
  /* The key corresponds to the page itself, remove the page offset */
  dummy.virtual_address = virtual_address;

  struct hash_elem * retrieved_ = hash_delete(hash, &dummy.h_elem);

  /* If the entry was not found, returns NULL */
  if(retrieved_ == NULL) {
    return NULL;
  }
  struct supplementary_page_entry * retrieved =
                hash_entry(retrieved_, struct supplementary_page_entry, h_elem);

  return retrieved;
}

