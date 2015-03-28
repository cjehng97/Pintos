#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/pte.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/block.h"
#include "vm/file_table.h"
/* Macros used for retrieving arguments off the interrupt frame stack */
#define GET_ARGS1(type1, function) \
    pointer_sanitize(f->esp+4); \
    f->eax = function ( \
        *((type1*) (f->esp+4)) \
        );

#define GET_ARGS2(type1, type2, function) \
    pointer_sanitize(f->esp+4); \
    pointer_sanitize(f->esp+8); \
    f->eax = function ( \
        *((type1*) (f->esp+4)), \
        *((type2*) (f->esp+8)) \
        );

#define GET_ARGS3(type1, type2, type3, function) \
    pointer_sanitize(f->esp+4); \
    pointer_sanitize(f->esp+8); \
    pointer_sanitize(f->esp+12); \
    f->eax = function ( \
        *((type1*) (f->esp+4)), \
        (void*) *((uint32_t*) (f->esp+8)), \
        *((type3*) (f->esp+12)) \
        );

/* Lock for the file system */
static struct lock filesys_lock;

/* The thirteen system calls */
static int halt (void);
static int exit (int status);
static pid_t exec (const char *file);
static int wait (pid_t);
static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static int open (const char *file);
static size_t filesize (int fd);
static size_t read (int fd, void *buffer, off_t length);
static int write (int fd, const void *buffer, unsigned length);
static int seek (int fd, unsigned position);
static unsigned tell (int fd);
static int close (int fd);

/* Task 3 system calls */
static mapid_t mmap (fd_t fd, void *addr);
static bool munmap (mapid_t mapping);


/* Local helper functions */
static int intr_frame_is_not_valid(struct intr_frame *);
static void syscall_handler (struct intr_frame *);
static int get_user (const uint8_t *uaddr) UNUSED;
static bool is_not_valid_ptr(const void * ptr);
static struct file * get_file(fd_t fd);
static int write_to_console(const char *buffer, unsigned length);
static int write_to_file(int fd, const char * buffer, unsigned length);
static off_t read_from_console(char * buffer, off_t length);
static off_t read_from_file(int fd, char * buffer, off_t length);
static inline bool is_executable_file(const char * file);
static inline int allocate_fd_for_file(struct file * new_file);
static void pointer_sanitize(const void * ptr);
static void pointer_sanitize_range(const void *start, off_t length);
static bool valid_fd(fd_t fd, struct file ** file);
static bool valid_addr(struct file * file, off_t * file_len, void * addr);
static bool add_new_mapping(mapid_t new_mapid, struct file * file, void * addr, off_t file_len);
static bool mapped_over_existing_pages(void * addr, off_t file_len);
/* PRE: None.
   POST: Initialises the system call handler and the file system lock. */
void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}



/* PRE: The input is a valid pointer to the interrupt frame.
   POST: Handles the system calls. */
static void
syscall_handler (struct intr_frame *f)
{
  if(intr_frame_is_not_valid(f)) {
    process_kill();
  }
  pointer_sanitize(f->esp);
  int32_t syscall_number = *((int32_t*) f->esp);
  thread_current()->f = f;
  switch (syscall_number) {
  case SYS_HALT:
    halt();
    break;
  case SYS_EXIT:
    GET_ARGS1(int, exit)
    break;
  case SYS_EXEC:
    GET_ARGS1(const char *, exec)
    break;
  case SYS_WAIT:
    GET_ARGS1(pid_t, wait)
    break;
  case SYS_CREATE:
    GET_ARGS2(const char *, unsigned, create)
    break;
  case SYS_REMOVE:
    GET_ARGS1(const char *, remove)
    break;
  case SYS_OPEN:
    GET_ARGS1(const char *, open)
    break;
  case SYS_FILESIZE:
    GET_ARGS1(int, filesize)
    break;
  case SYS_READ:
    GET_ARGS3(int, int, off_t, read)
    break;
  case SYS_WRITE:
    GET_ARGS3(int, void *, unsigned, write)
    break;
  case SYS_SEEK:
    GET_ARGS2(int, unsigned, seek)
    break;
  case SYS_TELL:
    GET_ARGS1(int, tell)
    break;
  case SYS_CLOSE:
    GET_ARGS1(int, close)
    break;
  case SYS_MMAP:
    GET_ARGS2(fd_t, void *, mmap)
    break;
  case SYS_MUNMAP:
    GET_ARGS1(mapid_t, munmap)
    break;
  }
}


/* PRE: None.
   POST: Terminates Pintos by calling shutdown_power_off() (declared in
         ‘devices/shutdown.h’). */
static int
halt (void)
{
  shutdown_power_off();
  NOT_REACHED();
}

/* PRE: The input is a valid interger representing an exit status.
   POST: Terminates the current user program, sending its exit status to the
         kernel. If the process’s parent waits for it, this is the status that
         will be returned. Conventionally, a status of 0 indicates success and
         nonzero values indicate errors. */
static int
exit (int status)
{
  thread_current()->process_wrapped->exit_status = status;
  thread_exit();

  NOT_REACHED();
}

/* PRE: The input is a valid pointer to char representing a file name.
   POST: Runs the executable whose name is given in command line, passing any
         given arguments, and returns the new process’s program id (pid). It
         must return pid -1, which otherwise should not be a valid pid, if the
         program cannot load or run for any reason. Thus, the parent process
         cannot return from the exec until it knows whether the child process
         successfully loaded its executable. */
static pid_t 
exec (const char *file)
{
  pointer_sanitize(file);

  int child_tid = process_execute(file);

  if(child_tid < 0) {
     return -1;
  }

  struct list_elem * it;
  struct process * pr = NULL;
  LIST_ITERATE(it, thread_current()->child_processes) {
    pr = list_entry(it, struct process, elem);
    if (pr->tid == child_tid) {
      break;
    }
  }

  sema_down(&pr->loaded);

  if (pr->loading_failed) {
    return -1;
  }

  return child_tid;

}

/* PRE: The input is a valid pid.
   POST: Waits for a child process pid and retrieves the child’s exit status. */
static int 
wait (pid_t thread_id)
{
  return process_wait(thread_id);
}

/* PRE: The input is a valid pointer to char representing a file name.
   POST: Creates a new file called file initially initial size bytes in size.
         Returns true if successful, false otherwise. Creating a new file does 
         not open it: opening the new file is a separate operation which would
         require a open system call. The file is created as follows:
          - Sanitizes the string
          - If the initial size of the file is too large (checked by the
            create file function), returns false
          - Else, uses the file system to write the file to the given
            destination */
static bool
create (const char *file, unsigned initial_size)
{

  pointer_sanitize(file);


  lock_acquire(&filesys_lock);
  bool ret = filesys_create(file, initial_size);
  lock_release(&filesys_lock);

  return ret;
}

/* PRE: The input is a valid pointer to char representing a file name.
   POST: Deletes the file called file. Returns true if successful, false
         otherwise. A file may be removed regardless of whether it is open or
         closed, and removing an open file does not close it. */
static bool 
remove (const char *file)
{
  pointer_sanitize(file);
  lock_acquire(&filesys_lock);
  filesys_remove(file);
  lock_release(&filesys_lock);

  return true;
}

// the same thing should happen for all syscalls
/* PRE: The input is a valid pointer to char representing a file name.
   POST: Opens the file given as an input. Returns a nonnegative integer handle
         called a “file descriptor” (fd), or -1 if the file could not be opened.
   NOTE: File descriptors numbered 0 and 1 are reserved for the console:
         fd 0 (STDIN_FILENO) is standard input,
         fd 1 (STDOUT_FILENO) is standard output.
         The open system call will never return either of these file
         descriptors, which are valid as system call arguments only as
         explicitly described below.
         Each process has an independent set of file descriptors. File
         descriptors are not inherited by child processes.
         When a single file is opened more than once, whether by a single
         process or di↵erent processes, each open returns a new file descriptor.
         Different file descriptors for a single file are closed independently
         in separate calls to close and they do not share a file position. */
static int 
open (const char * file)
{
  pointer_sanitize(file);

  lock_acquire(&filesys_lock);
  struct file * new_file = filesys_open(file);
  lock_release(&filesys_lock);

  if (new_file == NULL) {
    return -1;
  }
  if (is_executable_file(file)) {
    file_deny_write(new_file);
  }

  return allocate_fd_for_file(new_file);
}

/* PRE: The input is a file descriptor.
   POST: Returns the size, in bytes, of the file open as fd. */
static size_t
filesize (int fd)
{
  struct file * file = get_file(fd);

  if (file == NULL) {
    return 0;
  }

  lock_acquire(&filesys_lock);
  off_t ret = file_length(file);
  lock_release(&filesys_lock);

  return ret;
}

/* PRE: The first argument is a file descriptor. The second argument is a valid
        pointer to the buffer.
   POST: Reads size bytes from the file open as fd into bu↵er. Returns the
         number of bytes actually read (0 at end of file), or -1 if the file 
         could not be read (due to a condition other than end of file). */
static size_t
read (int fd , void *buffer_ , off_t length )
{
  if(length < 0 || fd == 1) {
    return -1;
  }
  //printf("Sanitizing a pointer\n");
  thread_current()->reserved_buffer = true;
  pointer_sanitize(buffer_);
  thread_current()->reserved_buffer = false;
  //  pointer_sanitize_range(buffer_, length);
  char * buffer = (char * )(buffer_);
  //printf("Pointers are sanitized\n");
  if(fd == 0) {
    return read_from_console(buffer, length);
  } else {
    //printf("About to read from pointer\n");
    return read_from_file(fd, buffer, length);
  }
}

/* PRE: The first argument is a file descriptor. The second argument is a valid
        pointer to the buffer.
   POST: Writes size bytes from buffer to the open file fd. Returns the number
         of bytes actually written, which may be less than size if some bytes 
         could not be written.
         Writing past end-of-file would normally extend the file, but file
         growth is not implemented by the basic file system. The expected
         behavior is to write as many bytes as possible up to end-of-file and
         return the actual number written, or 0 if no bytes could be written at
         all. */
static int 
write (int fd, const void * buffer_, unsigned length)
{
  pointer_sanitize_range(buffer_, length);
  char * buffer = (char * )(buffer_);
  if (fd == 1) {
    return write_to_console(buffer, length);
  } else {
    return write_to_file(fd, buffer, length);
  }
}

/* PRE: The first argument is a file descriptor, the second argument is the
        position to look at.
   POST: Changes the next byte to be read or written in open file fd to
         position, expressed in bytes from the beginning of the file.
         (Thus, a position of 0 is the file’s start.)
         A seek past the current end of a file is not an error. A later read
         obtains 0 bytes, indicating end of file. A later write extends the
         file, filling any unwritten gap with zeros. (However, in Pintos files
         have a fixed length until task 4 is complete, so writes past end of
         file will return an error). */
static int
seek (int fd, unsigned position)
{
  struct file * f = get_file(fd);

  if (f == NULL) {
    return 0;
  }

  f->pos = position;
  return 0;
}

/* PRE: The input is a file descriptor.
   POST: Returns the position of the next byte to be read or written in open
         file fd, expressed in bytes from the beginning of the file. */
static unsigned 
tell (int fd)
{
  struct file * f = get_file(fd);

  if (f == NULL) {
    return -1;
  }

  return f->pos;
}

/* PRE: The input is a file descriptor.
   POST: Closes the file identified by a fd.
   NOTE: This should be called  on all open file descriptors when a process
         ends, we should not close the file if there are open any file
         descriptors opened on it (release the file descriptor into the pool of
         available file descriptors get the file associated with the file
         descriptor */
static int
close (int fd)
{
  struct list_elem * itp;
  struct fd_list_elem_ * ep = NULL;

  LIST_ITERATE(itp, thread_current()->fd_table) {
    ep = list_entry(itp, struct fd_list_elem_, elem);
    if (ep->fd == fd) {
      break;
    }
  }

  if(ep != NULL){
    list_remove(&(ep->elem));
    lock_acquire(&filesys_lock);
    file_close(ep->file);
    lock_release(&filesys_lock);
    free(ep);
  }

  return 0;
}

static bool
valid_fd(fd_t fd, struct file ** file)
{
  struct list_elem * itp;
  struct fd_list_elem_ *ep = NULL;
  *file = NULL;
  LIST_ITERATE(itp, thread_current()->fd_table) {
    ep = list_entry(itp, struct fd_list_elem_, elem);
    if (ep->fd == fd) {
      *file = ep->file;
    }
  }
  return fd >= 2 && *file != NULL;

}

static bool
valid_addr(struct file * file, off_t * file_len, void * addr) {
  *file_len = file_length(file);  
  
  return (*file_len > 0) && !((uint32_t)addr & PTE_FLAGS) && (addr != NULL) 
    && !mapped_over_existing_pages(addr, *file_len);
}

static bool
add_new_mapping(mapid_t new_mapid, struct file * file, void * addr, off_t file_len) {
 
  file_table_insert_mmap(&thread_current()->file_table, &thread_current()->mmap_file_table, file, 0, addr, file_len, PGSIZE - file_len%PGSIZE, true,  new_mapid);
  bool result = load_segment( file, 0, addr, file_len, PGSIZE - file_len%PGSIZE, true);
  file_seek(file, 0);
  return result;
}
  
static bool
overlaps(const void * addr) {
  return pagedir_get_page(thread_current()->pagedir, addr) != NULL;
}

static bool
mapped_over_existing_pages(void * addr, off_t file_len) {

  if ((uint32_t) addr >= (uint32_t) thread_current()->f->esp) {
    return true;
  }
  
  while (file_len > 0) {
    if (overlaps(addr)) {
      return true;
    }
    file_len -= PGSIZE;
    addr += PGSIZE;
  }
  
  return false;
}

static mapid_t
mmap (fd_t fd, void *addr){

  struct file * file;
  off_t file_len;
  if(!valid_fd(fd, &file) || !valid_addr(file, &file_len, addr))
    return -1;

  mapid_t new_mapid = allocate_mapid();
  add_new_mapping(new_mapid, file, addr, file_len);
  return new_mapid;
}


/*
    Unmaps the mapping designated by mapping, which must be a mapping ID returned by a
	previous call to mmap by the same process that has not yet been unmapped.
	All mappings are implicitly unmapped when a process exits, whether via exit or by any
	other means. When a mapping is unmapped, whether implicitly or explicitly, all pages written
	to by the process are written back to the file, and pages not written must not be. The pages are
	then removed from the process’s list of virtual pages.
 */

static bool
munmap(mapid_t mapping)
{
  struct thread * t = thread_current();
  struct mmap_file_table_entry * mmap = mmap_file_table_find_entry(
      &t->mmap_file_table, mapping);
  if (mmap != NULL) {

    mmap_file_table_unmap(mmap, t);

    hash_delete(&thread_current()->mmap_file_table, &mmap->h_elem);

  }
  return true;
}


////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// HELPER FUNCTIONS ///////////////////////////////
////////////////////////////////////////////////////////////////////////////////


/* PRE: The argument is a valid file descriptor.
   POST: Retrieves the file associated with the given file descriptor. */
static struct file *
get_file(fd_t fd)
{
  struct list_elem * itp;
  struct fd_list_elem_ *ep = NULL;
  LIST_ITERATE(itp, thread_current()->fd_table) {
    ep = list_entry(itp, struct fd_list_elem_, elem);
    if (ep->fd == fd) {
      return ep->file;
    }
  }

  return NULL;
}


/* PRE: The argument is a valid pointer to a buffer.
   POST: Reads from the console and returns the length. */
static off_t 
read_from_console(char * buffer, off_t length) 
{
  int i;

  for (i = 0; i < length; ++i) {
    buffer[i] = input_getc();
  }

  return length;
}

/* PRE: The first argument is a valid file descriptor, the second argument is a
        valid pointer to a buffer.
   POST: Reads from the give file fd and returns the number of characters
         actually read.  */
static off_t 
read_from_file(int fd, char * buffer, off_t length)
{
  struct file * f = get_file(fd);

  if (f == NULL) {
    return -1;
  }
  lock_acquire(&filesys_lock);
  thread_current()->reserved_buffer = true;
  off_t ret = file_read(f, buffer, length);
  thread_current()->reserved_buffer = false;
  lock_release(&filesys_lock);

  return ret;
}

/* PRE: The first argument is a valid pointer to a buffer.
   POST: Writes to the console and returns 0. */
static int
write_to_console(const char * buffer, unsigned length) 
{
  lock_acquire(&filesys_lock);
  putbuf(buffer, length);
  lock_release(&filesys_lock);

  return 0;
}


/* PRE: The first argument is a valid file descriptor, the second argument is a
        valid pointer to a buffer.
   POST: Writes to the given file fd and returns the number of bytes actually
         written if successful, 0 otherwise. */
static int
write_to_file(int fd, const char * buffer, unsigned length) 
{
  struct file * f = get_file(fd);
  if (f == NULL) {
    return 0;
  }
  lock_acquire(&filesys_lock);
  int result = file_write(f, buffer, length);
  lock_release(&filesys_lock);
  return result;
}

static inline bool
is_executable_file(const char * file) 
{
  return strcmp(file, thread_current()->name) == 0;
}

/* PRE: The argument is a valid pointer to struc file.
   POST: Allocates a unique file descriptor for the given file. */
static inline int
allocate_fd_for_file(struct file * new_file) 
{

  struct fd_list_elem_ *new_fd_list_element =
      (struct fd_list_elem_ *) malloc(sizeof (struct fd_list_elem_));
  new_fd_list_element->fd = allocate_fd();;
  new_fd_list_element->file = new_file;
  list_push_back(&(thread_current()->fd_table), &(new_fd_list_element->elem));

  return new_fd_list_element->fd;
}


/* PRE: The argument is a valid pointer to struc intr_frame.
   POST: Cleans up. */
void
clean_up(void)
{

  struct list_elem * it;
  struct list_elem * aux;
  struct fd_list_elem_ * rem;

  LIST_ITERATE(it, thread_current()->acquired_locks) {
    struct lock * l = list_entry(it, struct lock, elem);
    it = it->prev;
    lock_release(l);
  }

  LIST_ITERATE(it, (thread_current()->fd_table)) {
    rem = list_entry(it, struct fd_list_elem_, elem);
    aux = it;
    it = it->prev;

    list_remove(aux);

    lock_acquire(&filesys_lock);
    file_close(rem->file);
    lock_release(&filesys_lock);
    free(rem);
  }

}

/* PRE: The argument is a valid pointer to struc intr_frame.
   POST: Initialize processes booting process? Everytime a process gets created
         add it to 'processes'. Everytime a process requests to open a file, it 
         should look through the list of processes, find the element that
         corresponds to the current process p then create a file through the 
         filesys interface 'file', if fds is empty then create a new fd 'f' and
         create a struct fd_, from f and file. */
static int
intr_frame_is_not_valid(struct intr_frame *f)
{
  return is_not_valid_ptr(f->esp) ? 1 : 0;
}

/* PRE: None.
   POST: Returns True if the argument is an invalid pointer, False otherwise. */
static bool
is_not_valid_ptr(const void * ptr)
{
  if( ptr != NULL && (uint32_t)ptr < (((uint32_t)PHYS_BASE) - 4)
      && get_user((uint8_t *)ptr) != -1)
    return 0;
  return 1;
}

/* PRE: None.
   POST: If the given pointer is valid, sanitises it. */
static void
pointer_sanitize(const void * ptr)
{
  if (is_not_valid_ptr(ptr)) {
    process_kill();
  }
}


static void
pointer_sanitize_range(const void *start, off_t length)
{
	if (start + length < start) {
		process_kill();
	}
	int32_t i;
	for (i = 0; i < length; i++) {
		pointer_sanitize(start + i);
	}
}

/* PRE: The given address must be below PHYS_BASE.
   POST: Reads a byte at the given user virtual address UADDR. Returns the byte
         value if successful, -1 if a segfault occurred. */
static int
get_user (const uint8_t *uaddr)
{
  ASSERT ((void*) uaddr < PHYS_BASE);
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

void filesys_lock_acquire(){
	lock_acquire(&filesys_lock);
}

void filesys_lock_release(){
	lock_release(&filesys_lock);
}

