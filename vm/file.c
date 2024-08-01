/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
/* ------ Project 3 ------ */
#include <stdio.h>
#include <round.h>
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "threads/init.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "vm/file.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

  struct file_page *file_page UNUSED = &page->file;
  return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
  struct file_page *file_page = &page->file;
  file_info           *f_info = file_page->aux;

  page->va = (void *)((uint64_t)page->va | PTE_P);
  lazy_load_segment (page, f_info);

  return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
  struct file_page *file_page = &page->file;

  if (file_page->aux) {
    file_info *f_info = page->file.aux;

    if (pml4_is_dirty (thread_current ()->pml4, page->va) || pml4_is_dirty (base_pml4, page->frame->kva)) {
      file_write_at (f_info->file, page->frame->kva, f_info->read_bytes, f_info->ofs);
    }
  }

  pml4_set_dirty (thread_current ()->pml4, page->va, 0);
  pml4_clear_page (thread_current ()->pml4, pg_round_down (page->va));

  page->va = (void *)((uint64_t)page->va & ~PTE_P);
  return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
  struct file_page *file_page = &page->file;

  if (file_page->aux) {
    file_info *f_info = page->file.aux;

    if (pml4_is_dirty (thread_current ()->pml4, page->va)) {
      file_write_at (f_info->file, page->frame->kva, f_info->read_bytes, f_info->ofs);
    }
    free (file_page->aux);
  }

  if (page->frame) {
    list_remove (&page->frame->f_elem);
    free (page->frame);
  }

  pml4_clear_page (thread_current ()->pml4, pg_round_down (page->va));
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable, struct file *file, off_t offset) {
  void *init_addr = addr;
  uint32_t init_length = length;
  uint32_t read_bytes = file_length (file);

  while ((int)length > 0) {

    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    file_info *f_info;
    if (!(f_info = malloc (sizeof (file_info)))) {
      return NULL;
    }
    f_info->file = file;
    f_info->read_bytes = page_read_bytes;
    f_info->ofs = offset;

    if (!vm_alloc_page_with_initializer (VM_FILE, addr, writable, lazy_load_segment, f_info)) {
      return NULL;
    }

    read_bytes -= page_read_bytes;
    addr += PGSIZE;
    offset += page_read_bytes;
    length -= PGSIZE;
  }
  struct page *page = spt_find_page (&thread_current ()->spt, init_addr);
  page->file_length = init_length;
  return init_addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
  struct thread *curr = thread_current ();
  struct page *page = spt_find_page (&curr->spt, addr);

  uint32_t rep = (page->file_length % PGSIZE) == 0
    ? page->file_length / PGSIZE
    : (page->file_length / PGSIZE) + 1;

  while (rep--) {
    hash_delete (&curr->spt.spt_hash, &page->h_elem);
    vm_dealloc_page (page);

    addr += PGSIZE;
    page = spt_find_page (&curr->spt, addr);
  }
}