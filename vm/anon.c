/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
/* ------ Project 3 ------ */
#include <stdio.h>
#include "kernel/bitmap.h"
#include "threads/malloc.h"
#include "threads/init.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* ------ Project 3 ------ */
static struct bitmap *swap_bitmap;

#define SWAP_SEGMENT (PGSIZE / DISK_SECTOR_SIZE)

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

#define NUM_PER_LINE 32 // DEBUG
// DEBUG
static void page_dump (struct page *page, int bytes) {
  unsigned char *p = pg_round_down (page->va);
  printf ("[DBG] dumping page at va = %p", page->va);
  for (int i = 0; i < bytes; i++) {
    if (i % NUM_PER_LINE == 0) {
      printf ("\n{%s} #%3d | ", thread_current ()->name, i / NUM_PER_LINE);
    }
    printf ("%2d", p[i]);
  }
  printf ("\n[DBG] dump done\n");
}

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
  swap_disk = disk_get (1, 1);
  swap_bitmap = bitmap_create (disk_size (swap_disk) / SWAP_SEGMENT);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
  return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;

  void *addr = pg_round_down (page->frame->kva);
  for (int i = 0; i < SWAP_SEGMENT; i++) {
    disk_read (swap_disk, (anon_page->swap_idx * SWAP_SEGMENT) + i, addr + (DISK_SECTOR_SIZE * i));
  }
  page->va = (void *)((uint64_t)page->va | PTE_P);

  bitmap_set (swap_bitmap, anon_page->swap_idx, false);
  anon_page->swap_idx = -1;

  return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;

  int bit_idx = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);
  if (bit_idx == BITMAP_ERROR) {
    PANIC (" ANON_SWAP_ERROR : NOT FOUND BITMAP\n");
  }

  void *addr = pg_round_down (page->frame->kva);
  for (int i = 0; i < SWAP_SEGMENT; i++) {
    disk_write (swap_disk, (bit_idx * SWAP_SEGMENT) + i, addr + (DISK_SECTOR_SIZE * i));
  }

  pml4_clear_page (thread_current ()->pml4, pg_round_down (page->va));
  anon_page->swap_idx = bit_idx;

  page->va = (void *)((uint64_t)page->va & ~PTE_P);
  return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
  struct anon_page *anon_page = &page->anon;
  if (anon_page->aux) {
    free (anon_page->aux);
  }

  if (page->frame) {
    list_remove (&page->frame->f_elem);
    free (page->frame);
  }
}