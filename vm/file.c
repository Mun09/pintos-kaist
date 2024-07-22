/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

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
void vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	struct uninit_page *uninit = &page->uninit;
	// vm_initializer *init = uninit->init;
	void *aux = uninit->aux;

	/* Set up the handler */
	page->operations = &file_ops;

	memset(uninit, 0, sizeof(struct uninit_page));

	struct lazy_load_info *info = (struct lazy_load_info *)aux;
	struct file_page *file_page = &page->file;
	file_page->file = info->file;
	file_page->length = info->page_read_bytes;
	file_page->offset = info->offset;
	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;

	ASSERT(page->frame->kva == kva); // #ifdef DBG check

	void *addr = page->va;
	//struct thread *t = thread_current();

	//aren't these already set in vm_do_claim_page?
	//page->frame->kva = kva; 
	//pml4_set_page(t->pml4, addr, kva, true); // writable true, as we are writing into the frame

	struct file *file = file_page->file;
	size_t length = file_page->length;
	off_t offset = file_page->offset;

	if(file_read_at(file, kva, length, offset) != length){
		// TODO - Not properly written-back
	}
	return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	void *addr = page->va;
	struct thread *t = thread_current();

	if(pml4_is_dirty(t->pml4, addr)){
		struct file *file = file_page->file;
		size_t length = file_page->length;
		off_t offset = file_page->offset;
		void *kva = page->frame->kva;
		if(file_write_at(file, kva, length, offset) != length){
			// TODO - Not properly written-back
		}
	}

	// access to page now generates fault
	pml4_clear_page(t->pml4, addr);
	page->frame->page = NULL;
	page->frame = NULL;
	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	close(file_page->file);
}

// used in lazy allocation - from process.c
// 나중에 struct file_page에 vm_initializer *init 같은거 만들어서 uninit의 init 함수 (lazy_load_segment) 넘겨주는 식으로 리팩토링 
// -> X uninit page 만드는거
bool
lazy_load_segment_for_file(struct page *page, void *aux)
{
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
	struct lazy_load_info * lazy_load_info = (struct lazy_load_info *)aux;
	struct file * file = lazy_load_info->file;
	size_t page_read_bytes = lazy_load_info->page_read_bytes;
	size_t page_zero_bytes = lazy_load_info->page_zero_bytes;
	off_t offset = lazy_load_info->offset;

	file_seek(file, offset);

	//vm_do_claim_page(page);
	ASSERT (page->frame != NULL); 	//이 상황에서 page->frame이 제대로 설정돼있는가?
	void * kva = page->frame->kva;
	if (file_read(file, kva, page_read_bytes) != (int)page_read_bytes)
	{
		//palloc_free_page(page); // #ifdef DBG Q. 여기서 free해주는거 맞아?
		free(lazy_load_info);
		return false;
	}

	memset(kva + page_read_bytes, 0, page_zero_bytes);
	free(lazy_load_info);

	file_seek(file, offset); // may read the file later - reset fileobj pos

	return true;
}


/* Do the mmap */
// similar design with load_segment - map consecutive pages until length runs out
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {

	// ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	// ASSERT(ofs % PGSIZE == 0);


	void *start_addr = addr; // return value or in case of fail - free from this addr
	struct thread *t = thread_current();
	struct page *page;
	int page_cnt = 1; // How many consecutive pages are mapped with file?

	size_t flen = file_length(file) - offset; // file left for reading

	// file_seek(file, offset); // change offset itself
	
	// allocate at least one page
	// throw off data that sticks out 
	while(length > 0){
		// Fail : pages mapped overlaps other existing pages or kernel memory
		if(spt_find_page(&t->spt, addr) != NULL || is_kernel_vaddr(addr)){
			void *free_addr = start_addr; // get page from this user vaddr and destroy them
			while(free_addr < addr){
				// free allocated uninit page
				page = spt_find_page(&t->spt, free_addr);

				// destroy(page); // uninit destroy - free aux
				// free(page->frame);
				// free(page);
				// remove_page(page);
				spt_remove_page(&t->spt, page);


				free_addr += PGSIZE;
			}
			return NULL;
		}

		size_t page_read_bytes = MIN(length, flen) < PGSIZE ? MIN(length, flen) : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		#ifdef DBG
		printf("(do_mmap) File length %d - read length %d\n", file_length(file), length);
		#endif

		// file info to load onto memory once fault occurs
		struct lazy_load_info *lazy_load_info = malloc(sizeof(struct lazy_load_info));
		lazy_load_info->file = file_reopen(file); // mmap-close - closing file after mmap
		lazy_load_info->page_read_bytes = page_read_bytes;
		lazy_load_info->page_zero_bytes = page_zero_bytes;
		lazy_load_info->offset = offset;
		void *aux = lazy_load_info;
		if (!vm_alloc_page_with_initializer(VM_FILE, addr,
											writable, lazy_load_segment_for_file, aux))
			return NULL;

		// record page_cnt
		page = spt_find_page(&t->spt, addr);
		page->page_cnt = page_cnt;

		offset += page_read_bytes;
		flen -= page_read_bytes;
		length -= length < PGSIZE ? length : PGSIZE; // prevent unsigned underflow
		addr += PGSIZE;
		page_cnt++;
	}

	return start_addr;
}

// /* Do the munmap */
// void
// do_munmap (void *addr) {
// }

// bool lazy_load_segment_for_file(struct page *page, void *aux) {
// 	/* TODO: Load the segment from the file */
// 	/* TODO: This called when the first page fault occurs on address VA. */
// 	/* TODO: VA is available when calling this function. */
// 	struct lazy_load_info * lazy_load_info = (struct lazy_load_info *)aux;
// 	struct file * file = lazy_load_info->file;
// 	size_t page_read_bytes = lazy_load_info->page_read_bytes;
// 	size_t page_zero_bytes = lazy_load_info->page_zero_bytes;
// 	off_t offset = lazy_load_info->offset;

// 	file_seek(file, offset);

// 	//vm_do_claim_page(page);
// 	ASSERT (page->frame != NULL); 	//이 상황에서 page->frame이 제대로 설정돼있는가?
// 	void * kva = page->frame->kva;
// 	if (file_read(file, kva, page_read_bytes) != (int)page_read_bytes)
// 	{
// 		//palloc_free_page(page); // #ifdef DBG Q. 여기서 free해주는거 맞아?
// 		free(lazy_load_info);
// 		return false;
// 	}

// 	memset(kva + page_read_bytes, 0, page_zero_bytes);
// 	free(lazy_load_info);

// 	file_seek(file, offset); // may read the file later - reset fileobj pos

// 	return true;
// }

/* Do the munmap */
void
do_munmap (void *addr) {
	struct thread *t = thread_current();
	struct page *page;

	page = spt_find_page(&t->spt, addr);
	//int prev_cnt = 0;
	int prev_cnt = page->page_cnt - 1; //if the file size is bigger than memmory space, first page of consecutive file-pages in memory is not the first page of the file.

	// Check if the page is file_page or uninit_page to be transmuted into file_page and then its consecutive
	while(page != NULL 
		&& (page->operations->type == VM_FILE 
			|| (page->operations->type == VM_UNINIT && page->uninit.type == VM_FILE))
		&& page->page_cnt == prev_cnt + 1){
		if(pml4_is_dirty(t->pml4, addr)){
			struct file *file = page->file.file;
			size_t length = page->file.length;
			off_t offset = page->file.offset;

			if(file_write_at(file, addr, length, offset) != length){
				// #ifdef DBG
				// TODO - Not properly written-back
			}
		}	

		prev_cnt = page->page_cnt;

		// removed from the process's list of virtual pages.
		pml4_clear_page(thread_current()->pml4, page->va);
		// destroy(page);
		// free(page->frame);
		// free(page);
		//remove_page(page);
		// spt_remove_page(&t->spt, page);

		addr += PGSIZE;
		page = spt_find_page(&t->spt, addr);
	}
}