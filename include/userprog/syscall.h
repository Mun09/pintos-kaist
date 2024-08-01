#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/stddef.h"
#include "filesys/off_t.h"

void syscall_init (void);

struct lock file_rw_lock;

/* --- Project 3 : Memory Mapped Files --- */
void *mmap (void *addr, size_t length, int writable, int fd, off_t offset);
void munmap (void *addr);

#endif /* userprog/syscall.h */
