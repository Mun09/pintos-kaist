#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

typedef struct {
  struct file *file;
  size_t read_bytes;
  off_t ofs;
} file_info;

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

struct thread *get_child_with_pid(int pid);
void argument_stack(char **parse, int count, void **rsp);

struct lock load_lock;

bool lazy_load_segment (struct page *page, void *aux);

#endif /* userprog/process.h */
