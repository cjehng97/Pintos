#include "vm/file_table.h"
#include <hash.h>
#include <list.h>
#include <debug.h>
#include "threads/malloc.h"
#include "threads/synch.h" 
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include <stdio.h>


/* Hash table functions */
static bool hash_less_function(const struct hash_elem *h1, const struct hash_elem *h2, void * aux);
static unsigned hash_hash_function(const struct hash_elem *h, void * aux);
static void hash_action_function(struct hash_elem *h, void * aux);

/* File table functions */
static void file_table_delete_entry(struct hash * file_table, void * addr);
inline static struct file_table_entry * hash_find_entry(struct hash * file_table, void * file_addr);
inline static struct file_table_entry * hash_delete_entry(struct hash * file_table, void * file_addr);

/* Mmap Hash table functions */
static bool mmap_hash_less_function(const struct hash_elem *h1, const struct hash_elem *h2, void * aux);
static unsigned mmap_hash_hash_function(const struct hash_elem *h, void * aux);
inline static struct mmap_file_table_entry * mmap_hash_find_entry(struct hash * file_table, mapid_t mapid);
static void mmap_hash_action_function(struct hash_elem *e, void * aux);

/* Initialises the file table, which is responsible for tracking the file to
   load when a page fault occurs. */
void
file_table_init(struct hash * file_table, struct hash * mmap_file_table)
{
	hash_init(file_table, hash_hash_function, hash_less_function, NULL);
	hash_init(mmap_file_table, mmap_hash_hash_function, mmap_hash_less_function, NULL);
}


bool file_table_insert_mmap(struct hash * file_table,
    struct hash * mmap_file_table, struct file * file, off_t offset,
    void * vaddr, int read_bytes, int zero_bytes, bool writable,
    mapid_t mapid){

  /* Attempts to retrieve the given frame */
  struct file_table_entry * retrieved = hash_find_entry(file_table, vaddr);

  struct file_table_entry * new_elem;

  /* If the frame was not found in the frame table, creates a new one */
  if (retrieved == NULL) {

    /* Creates a new frame */
    new_elem =
          (struct file_table_entry *) malloc(sizeof(struct file_table_entry));

    /* If memory allocation failed */
    if(!new_elem) {
    	return false;
    }

    /* If memory allocation was succesful, sets up the frame fields */
    new_elem->file_addr = vaddr;
    new_elem->file = file;
    new_elem->file_page = offset;
    new_elem->read_bytes = read_bytes;
    new_elem->zero_bytes = zero_bytes;
    new_elem->flags |= writable? IS_WRITABLE: 0;
    new_elem->mapid = mapid;
    /* Inserts the new frame into the frame table */
    hash_insert(file_table, &new_elem->h_elem);
    

    /* Creates a new frame */
    struct mmap_file_table_entry * mmap_new_elem =
          (struct mmap_file_table_entry *) malloc(sizeof(struct mmap_file_table_entry));

    /* If memory allocation failed */
    if(!mmap_new_elem) {
    	return false;
    }

    mmap_new_elem->mapid = mapid;
    mmap_new_elem->file_addr = vaddr;
    mmap_new_elem->file = file;
    mmap_new_elem->file_len = read_bytes;


    hash_insert(mmap_file_table, &mmap_new_elem->h_elem);
  } else {
    new_elem = retrieved;
  }

  return true;

  
}


/* Inserts the given file inside the given file table. */
bool
file_table_insert(struct hash * file_table, struct file * file, off_t offset,
                  void * vaddr, int read_bytes, int zero_bytes, bool writable,
                  bool executable )
{
  struct file_table_entry * retrieved = hash_find_entry(file_table, vaddr);

  struct file_table_entry * new_elem;

  if (retrieved == NULL) {

    new_elem =
          (struct file_table_entry *) malloc(sizeof(struct file_table_entry));

    if(!new_elem) {
    	return false;
    }

    new_elem->file_addr = vaddr;
    new_elem->file = file;
    new_elem->file_page = offset;
    new_elem->read_bytes = read_bytes;
    new_elem->zero_bytes = zero_bytes;
    new_elem->flags |= executable ? IS_EXEC : 0;
    new_elem->flags |= writable ? IS_WRITABLE: 0;

    hash_insert(file_table, &new_elem->h_elem);

  } else {
    new_elem = retrieved;
  }

  return true;
}


/* Retrieves a file from the given file table. 
   Returns the file entry if found, NULL otherwise. */
struct file_table_entry *
file_table_find_entry(struct hash * file_table, void * file_addr)
{
	return hash_find_entry( file_table, file_addr );
}

void file_table_destroy(struct hash * file_table) {
}


struct mmap_file_table_entry *
mmap_file_table_find_entry(struct hash * mmap_file_table, mapid_t mapid)
{
	return mmap_hash_find_entry(mmap_file_table, mapid);
}




bool mmap_file_table_unmap(struct mmap_file_table_entry * mmap_file_table_entry, struct thread * t){

	/* For each page inside the file check if its dirty bit is set,
     if it is then write it to the file system
	   remove the file from the page table as well as the file table. */
	void * addr = mmap_file_table_entry->file_addr;
	int len     = mmap_file_table_entry->file_len;
	file_seek(mmap_file_table_entry->file, 0);
	file_table_delete_entry(&t->file_table, addr);
	while (len > 0)
	{
		if(pagedir_is_dirty(t->pagedir, addr)){
			file_write(mmap_file_table_entry->file, addr, len < PGSIZE ? len : PGSIZE);
		}

		release_page(t->pagedir, addr);

		/* Advance. */
		len -= PGSIZE;
		addr += PGSIZE;
	}
	file_seek(mmap_file_table_entry->file, 0);
	return true;
}

void mmap_file_table_destroy(struct hash * mmap_file_table) {
  hash_destroy(mmap_file_table, mmap_hash_action_function);
}



static void file_table_delete_entry(struct hash * file_table , void * addr ){
	  struct file_table_entry * entry = hash_find_entry(file_table, addr);
	  ASSERT(entry != NULL);
	  hash_action_function(&entry->h_elem, NULL);
	  hash_delete(file_table, &entry->h_elem);
}

/* Returns True if a file entry wrapped by h1 precedes a file entry wrapped by
   h2, False otherwise. */
static bool
hash_less_function(const struct hash_elem *h1,
                   const struct hash_elem *h2, void * aux UNUSED)
{
  struct file_table_entry *f1 = hash_entry(h1, struct file_table_entry, h_elem);
  struct file_table_entry *f2 = hash_entry(h2, struct file_table_entry, h_elem);
  return f1->file_addr - f2->file_addr;
}

/* Returns a hash value from the given hash element, i.e. a file address. */
static unsigned
hash_hash_function(const struct hash_elem *h, void * aux UNUSED)
{
  struct file_table_entry *f1 = hash_entry(h, struct file_table_entry, h_elem);
  return (unsigned) f1->file_addr;
}

static void
hash_action_function(struct hash_elem * h, void * aux UNUSED) {
	  struct file_table_entry *f1 = hash_entry(h, struct file_table_entry, h_elem);
	  if(f1->flags & IS_EXEC){
		  release_page(thread_current()->pagedir, f1->file_addr);
  	  }
}

/* Retrieves a file table entry from the file table.
   Returns this element if found, NULL otherwise. */
inline static struct file_table_entry *
hash_find_entry(struct hash * file_table, void * file_addr)
{
  struct file_table_entry dummy;
  dummy.file_addr = file_addr;

  struct hash_elem * retrieved_ = hash_find(file_table, &dummy.h_elem);

  /* If the entry was not found, returns NULL */
  if(retrieved_ == NULL) {
	  return NULL;
  }

  struct file_table_entry * retrieved =
                        hash_entry(retrieved_, struct file_table_entry, h_elem);

  return retrieved;
}

/* Deletes an entry from the hash table (structure wrapped by the file table).
   Returns that entry if found, NULL otherwise. */
inline static struct file_table_entry *
hash_delete_entry(struct hash * file_table, void * file_addr)
{
  struct file_table_entry dummy;
  dummy.file_addr = file_addr;

  struct hash_elem * retrieved_ = hash_delete(file_table, &dummy.h_elem);

  /* If the entry was not found, returns NULL */
  if(retrieved_ == NULL) {
    return NULL;
  }

  struct file_table_entry * retrieved =
                        hash_entry(retrieved_, struct file_table_entry, h_elem);

  return retrieved;
}

bool is_writable(struct file_table_entry * e) {
	return e->flags & IS_WRITABLE;
}


//=================HASH FUNCTIONS FOR MMAP HASH TABLE===========================


inline static struct mmap_file_table_entry *
mmap_hash_find_entry(struct hash * mmap_file_table, mapid_t mapid)
{
  struct mmap_file_table_entry dummy;
  dummy.mapid = mapid;
  struct hash_elem * retrieved_ = hash_find(mmap_file_table, &dummy.h_elem);

  /* If the entry was not found, returns NULL */
  if(retrieved_ == NULL) {
	  return NULL;
  }

  struct mmap_file_table_entry * retrieved =
                        hash_entry(retrieved_, struct mmap_file_table_entry, h_elem);

  return retrieved;
}


static unsigned
mmap_hash_hash_function(const struct hash_elem * h, void * aux UNUSED) {
  struct mmap_file_table_entry * e = hash_entry ( h, struct mmap_file_table_entry, h_elem);
  return (unsigned) e->mapid;
}


static bool
mmap_hash_less_function(const struct hash_elem *h1,
                   const struct hash_elem *h2, void * aux UNUSED)
{
  struct mmap_file_table_entry *f1 = hash_entry(h1, struct mmap_file_table_entry, h_elem);
  struct mmap_file_table_entry *f2 = hash_entry(h2, struct mmap_file_table_entry, h_elem);
  return f1->mapid - f2->mapid;
}

void mmap_hash_action_function(struct hash_elem *e, void * aux UNUSED){
	struct mmap_file_table_entry *f1 = hash_entry(e, struct mmap_file_table_entry, h_elem);
	//printf("Destroying the file table element from inside the hash destroy function\n");
	mmap_file_table_unmap(f1, thread_current());
}

