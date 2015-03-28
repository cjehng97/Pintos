#ifndef VM_FILE_TABLE_H
#define VM_FILE_TABLE_H

#include <list.h>
#include <hash.h>
#include "filesys/off_t.h"
#include "threads/thread.h"
#define IS_EXEC            1  /* 0th bit determines if file is executable */
#define IS_WRITABLE  (1 << 1) /* 2nd bit determines if file is writable*/


struct file_table_entry {
  void * file_addr;           /* Virtual address */
  struct file * file;         /* File struct corresponding to this file*/
  int read_bytes;             /* How many bytes have been read */
  int zero_bytes;             /* Padding: PGSIZE - read_bytes */
  uint32_t flags;             /* Bitmap containing flags for the access bits */
  int file_page;              /* Offset within the file that this file table
                                 entry corresponds */
  void * phys_loc;            /* Physical address */
  mapid_t mapid;              /* Mapped file ID */
  struct hash_elem h_elem;    /* Hash element used by the hash table */
};

struct mmap_file_table_entry {
  mapid_t mapid;              /* Mapped file ID */
  void * file_addr;           /* Virtual address */
  struct file * file;         /* File structure */
  int file_len;               /* File length */

  struct hash_elem h_elem;    /* Hash element used for the file table */
};


/* File page table functions */
void file_table_init(struct hash * file_table, struct hash * mmap_file_table);
bool file_table_insert(struct hash * file_table, struct file * file, off_t offset, void * vaddr, int read_bytes, int zero_bytes, bool writable, bool executable);
bool file_table_insert_mmap(struct hash * file_table, struct hash * mmap_file_table, struct file * file, off_t offset, void * vaddr, int read_bytes, int zero_bytes, bool writable, mapid_t mapid);
void file_table_destroy(struct hash * file_table);
struct file_table_entry * file_table_find_entry(struct hash * file_table, void * file_addr);
struct mmap_file_table_entry * mmap_file_table_find_entry(struct hash * mmap_file_table, mapid_t mapid);
bool mmap_file_table_unmap(struct mmap_file_table_entry  * mmap_file_table, struct thread * t);
void mmap_file_table_destroy(struct hash * mmap_file_table);
bool is_writable(struct file_table_entry * e);
#endif /* VM_FILE_TABLE_H */
