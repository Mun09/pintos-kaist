/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "kernel/bitmap.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

const int SECTORS_IN_PAGE = 8;

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1,1);

#ifdef DBG
	printf("disk size : %d\n", disk_size(swap_disk));
#endif

	bitcnt = disk_size(swap_disk)/SECTORS_IN_PAGE; // #ifdef Q. disk size decided by swap-size option?
	swap_table = bitmap_create(bitcnt); // each bit = swap slot for a frame
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	struct uninit_page *uninit = &page->uninit;
	memset(uninit, 0, sizeof(struct uninit_page));

	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	anon_page->swap_sec = -1;
	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;

	int swap_sec = anon_page->swap_sec;
	int swap_slot_idx = swap_sec / SECTORS_IN_PAGE;

	if(bitmap_test(swap_table, swap_slot_idx) == 0)
		//return false;
		PANIC("(anon swap in) Frame not stored in the swap slot!\n");

	page->frame->kva = kva;

	bitmap_set(swap_table, swap_slot_idx, 0);

	// ASSERT(is_writable(kva) != false);

	// disk_read is done per sector; repeat until one page is read
	for(int sec = 0; sec < SECTORS_IN_PAGE; sec++)
		disk_read(swap_disk, swap_sec + sec, page->frame->kva + DISK_SECTOR_SIZE * sec);
	
	// restore vaddr connection
	pml4_set_page(thread_current()->pml4, page->va, kva, true); // writable true, as we are writing into the frame

	anon_page->swap_sec = -1;
	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;

	// Find free slot in swap disk
	// Need at least PGSIZE to store frame into the slot 
	// size_t free_idx = bitmap_scan(swap_table, 0, SECTORS_IN_PAGE, 0);
	size_t free_idx = bitmap_scan_and_flip(swap_table, 0, 1, 0);

	if(free_idx == BITMAP_ERROR)
		PANIC("(anon swap-out) No more free swap slots!\n");

	int swap_sec = free_idx * SECTORS_IN_PAGE;

	// disk_write is done per sector; repeat until one page is written
	for(int sec = 0; sec < SECTORS_IN_PAGE; sec++)
		disk_write(swap_disk, swap_sec + sec, page->frame->kva + DISK_SECTOR_SIZE * sec);

	// access to page now generates fault
	pml4_clear_page(thread_current()->pml4, page->va);

	anon_page->swap_sec = swap_sec;

	page->frame->page = NULL;
	page->frame = NULL;

	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}