#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "vm/page.h"
#include "vm/file_table.h"

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);
static void* get_new_frame(enum palloc_flags flags);
static bool create_new_page(void * vaddr);
static bool grow_stack(void * vaddr, struct intr_frame * f);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}


/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      process_kill ();

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      process_kill ();
    }
}


/* PRE : Given flag that indicates which pool we try to retrieve a free frame
 * 		 is valid.
 * POST: Gets a new frame. If no frame is available, evicts one. */
static void* get_new_frame(enum palloc_flags flags) {
	void* kpage = palloc_get_page(flags);
	if (kpage == NULL ) {
		PANIC("Out of frames");
	}
	return kpage;
}


/* PRE : The virtual address in the page that is all-zeroed.
 * POST: Try to allocate a new frame to the page indicated by the virtual
 * 		 address. Return true if it is successful, false otherwise.
 */
static bool create_new_page(void * vaddr) {
	void* kpage = get_new_frame(PAL_USER | PAL_ZERO);
	return (pagedir_get_page (thread_current()->pagedir,
                            start_of_page(vaddr)) == NULL
	          && pagedir_set_page(thread_current()->pagedir,
                                start_of_page(vaddr), kpage, true));
}

/* PRE : None
 * POST: Return true if the given virtual address fits the heuristic measure of
 * 		 whether it can be pointing at the top of the stack which have
 * 		 not been allocated. That is, both vaddr and stack pointer are between
 * 	     PHYS_BASE and the bottom of the code segment, and virtual address is
 * 	     above where the stack pointer is pointing - 32.
 * 	     False if the given virtual address is pointing at somewhere which
 * 	     should not be part of the stack (yet).
 */

static bool grow_stack(void * vaddr_, struct intr_frame * f){
    uint32_t stack_ptr = (uint32_t)f->esp;
	uint32_t vaddr = (uint32_t) vaddr_;
	return (vaddr >  0x08048000)
		&& (vaddr < PHYS_BASE)
		&& (stack_ptr >  0x08048000)
		&& (stack_ptr < PHYS_BASE)
		&& (stack_ptr - PUSH_A_BYTES  <= vaddr);
}


/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to task 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f)
{

  bool not_present;  /* True: not-present page, False: writing r/o page. */
  bool write;        /* True: access was write, False: access was read. */
  bool user;         /* True: access by user, False: access by kernel. */
  void *fault_addr;  /* Fault address. */

  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

  /* Obtain the faulting address, i.e. the virtual address that was accessed to
     cause the fault.  The address may point to code or to data.
     It is not necessarily the address of the instruction that caused the fault
     (that is f->eip).

     See [IA32-v2a] "MOV--Move to/from Control Registers"
     and [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Turn interrupts back on (they were disbaled so that the reading the CR2 is
     ensured before it changes) */
  intr_enable ();
  /* Count the number of page faults. */
  page_fault_cnt++;

  if(!not_present) {
	  thread_current()->process_wrapped->exit_status = -1;
	  process_kill();
	  kill (f);
  }

  if(!user) {
	/* When we are potentially accessing in the buffer, use stack_grow to
	 * determine if the fault address is in a reasonable location.
	 * If it is not, one cannot access to a memory location that is not
	 * initialise. Kill it.
	 */

	f = thread_current()->f;
	if(!thread_current()->reserved_buffer){
	  thread_current()->process_wrapped->exit_status = -1;
	  process_kill();
	  kill (f);
    } 

  }

  lock_acquire(&thread_current()->spt_lock);
  struct supplementary_page_entry * retrieved =
      supplementary_find(&(thread_current()->supplementary_page_table), fault_addr);
  lock_release(&thread_current()->spt_lock);



  if(retrieved == NULL){/* If no element was found in the sup. page table */
      if(grow_stack(fault_addr, f)){
          create_new_page(fault_addr)? : PANIC("Could not create an all zero page");
      }
      else{
    	  //printf("killin.\n\n\n\n");
          thread_current()->process_wrapped->exit_status = -1;
          process_kill();
          kill (f);
      }
  } else { /* If an element was retrieved from the sup. page table */
  /* Look at the element (i.e. page) situation and behave consequently */
      switch(retrieved->page_sit) {
    /* If the page is all zeroed */
      case IS_ZERO: create_new_page(fault_addr) ? : PANIC("Could not create an all zero page");
    break;
    /* If the page is swapped */
      case IN_SWAP:
        swap_put_back(fault_addr);
        break;
    /* If the page was not loaded yet */
      case NOT_LOADED: lazy_load_page(start_of_page(fault_addr), write);
    break;
    /* If the page is in memory */
      case IN_MEMORY: PANIC("ERROR: This should not happen - potential error.");
    break;
    /* If the page situation is incorrect */
      default : PANIC("ERROR: Incorrect page situation!");
    break;
     }
  }
}
