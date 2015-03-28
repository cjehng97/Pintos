#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/file.h"
#include <stdbool.h>

typedef int fd_t;
typedef int pid_t;
typedef int tid_t;
typedef int mapid_t;


struct process
{
    tid_t tid;                       /* ID of the thread that this struct is
                                        associated with */

    struct semaphore wait_semaphore; /* Used to ensure the synchronization
                                        required in wait system call */

    struct semaphore loaded;         /* Used to ensure the synchronization
                                        required in exec systen call */

    int exit_status;                 /* Keeps track of the exit status.
                                        Required in wait system call */

    bool loading_failed;             /* Keeps track of whether loading of a
                                        user program was successful. Required
                                        in exec system call */

    bool waited_for;                 /* True if a parent has waited this
                                        process, false otherwise. */

    bool has_exited;                 /* True if the thread of tid has exited */

    bool should_be_deleted_by_child; /* True when the parent is dead
                                        -> this process should be deleted by
                                        child, false otherwise */

    struct list_elem elem;           /* Used by parents to keep the list of
                                        child processes */
};

tid_t process_execute(const char *file_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);
void process_init(void);
fd_t allocate_fd(void);
mapid_t allocate_mapid(void);
void process_kill(void);

bool install_page (void *upage, void *kpage, bool writable);

void lazy_load_page(void * vaddr, bool write);

/** Probably move this to the file sys files */

bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

struct fd_list_elem_
{
  fd_t fd;
  struct file *file;
  struct list_elem elem;
};

#endif /* userprog/process.h */
