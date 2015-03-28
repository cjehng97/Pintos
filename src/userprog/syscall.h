#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>
#include "threads/interrupt.h"

void syscall_init (void);

void clean_up(void);

#endif /* userprog/syscall.h */
