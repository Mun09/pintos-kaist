/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
/* P3 추가 */
bool delete_page (struct hash *pages, struct page *p);
unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED);
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);
struct list frame_table; 
void hash_action_copy (struct hash_elem *e, void *hash_aux);
void hash_action_destroy (struct hash_elem *e, void *aux);
static void vm_stack_growth (void *addr UNUSED);

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
/* 이니셜라이저를 사용하여 보류 중인 페이지 객체를 만듭니다. 
	페이지를 생성하려면 직접 작성하지 말고, 이 함수 또는 'vm_alloc_page'를 통해 수행합니다. */
//
bool vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable, vm_initializer *init, void *aux) {
	ASSERT (VM_TYPE(type) != VM_UNINIT)
	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type, 
							and then create "uninit" page struct by calling uninit_new. 
							You should modify the field after calling the uninit_new. */
		/* P3 추가 */
		bool (*initializer)(struct page *, enum vm_type, void *);
		switch(type){
			case VM_ANON: case VM_ANON|VM_MARKER_0: // 왜 두번째 케이스에서 저렇게 이중(?)으로 체크하지?
				initializer = anon_initializer;
				break;
			case VM_FILE:
				initializer = file_backed_initializer;
				break;
		}

		struct page *new_page = malloc(sizeof(struct page));
		uninit_new (new_page, upage, init, type, aux, initializer);

		new_page->writable = writable;
		// new_page->page_cnt = -1; // only for file-mapped pages

		/* TODO: Insert the page into the spt. */
		spt_insert_page(spt, new_page); // should always return true - checked that upage is not in spt
				
	#ifdef DBG
		printf("Inserted new page into SPT - va : %p / writable : %d\n", new_page->va, writable);
	#endif

		return true;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
//
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
    struct page dummy_page; dummy_page.va = pg_round_down(va); // dummy for hashing
    struct hash_elem *e;

    e = hash_find(&spt->spt_hash, &dummy_page.hash_elem);

	if(e == NULL)
		return NULL;

    return page = hash_entry(e, struct page, hash_elem);
}

/* Insert PAGE into spt with validation. */
//
bool spt_insert_page (struct supplemental_page_table *spt UNUSED, struct page *page UNUSED) {
	int succ = false;
	/* P3 추가 */
	struct hash_elem *e = hash_find(&spt->spt_hash, &page->hash_elem);
	if(e != NULL) // page already in SPT
		return succ; // false, fail

	// page not in SPT
	hash_insert (&spt->spt_hash, &page->hash_elem);	
	return succ = true;
}

/* P3 추가 */
bool delete_page (struct hash *pages, struct page *p) {
	if (hash_delete(pages, &p->hash_elem))
		return false;
	else
		return true;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */
	/* P3 추가 */
	// FIFO 방식 너무 무식한거 아님?
	victim = list_entry(list_pop_front(&frame_table), struct frame, elem); // FIFO algorithm
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
//
static struct frame *
vm_evict_frame (void) {
	/* TODO: swap out the victim and return the evicted frame. */
	struct frame *victim = vm_get_victim();
	if(victim == NULL) {
		return NULL;
	}

	#ifdef DBG_swap
		printf("(vm_evict_frame) frame %p(page %p) selected and now swapping out\n", victim->kva, victim->page->va);
	#endif
	if(victim->page != NULL){
		if(!swap_out(victim->page)) {
			return NULL;
		}
	}
	// Manipulate swap table according to its design
	return victim;
}

/* palloc() and get frame. 
	If there is no available page, evict the page and return it. 
	This always return valid address. 
	That is, if the user pool memory is full, 
	this function evicts the frame to get the available memory space.*/
//
static struct frame *vm_get_frame (void) {
	struct frame *frame = NULL;
	void *kva = palloc_get_page(PAL_USER);
	/* TODO: Fill this function. */

	/* P3 추가 */
	if (kva == NULL){ // NULL이면(사용 가능한 페이지가 없으면) 
		frame = vm_evict_frame(); // 페이지 삭제 후 frame 리턴
	}
	else{ // 사용 가능한 페이지가 있으면
		frame = malloc(sizeof(struct frame)); // 페이지 사이즈만큼 메모리 할당
		frame->kva = kva;
	}
	
	ASSERT (frame != NULL);
	// ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void vm_stack_growth (void *addr UNUSED) {
	vm_alloc_page(VM_ANON | VM_MARKER_0, addr, true); // Create uninit page for stack; will become anon page
	//bool success = vm_claim_page(addr);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	// return vm_do_claim_page (page);
	// Step 1. Locate the page that faulted in the supplemental page table
	void * fpage_uvaddr = pg_round_down(addr); // round down to nearest PGSIZE
	// void * fpage_uvaddr = (uint64_t)addr - ((uint64_t)addr%PGSIZE); // round down to nearest PGSIZE

	struct page *fpage = spt_find_page(spt, fpage_uvaddr);
	
	// Invalid access - Not in SPT (stack growth or abort) / kernel vaddr / write request to read-only page
	if(is_kernel_vaddr(addr)){
		return false;
	}

	else if (fpage == NULL){
		void *rsp = user ? f->rsp : thread_current()->rsp; // a page fault occurs in the kernel
		const int GROWTH_LIMIT = 32; // heuristic
		const int STACK_LIMIT = USER_STACK - (1<<20); // 1MB size limit on stack

		// Check stack size max limit and stack growth request heuristically
		if((uint64_t)addr > STACK_LIMIT && USER_STACK > (uint64_t)addr && (uint64_t)addr > (uint64_t)rsp - GROWTH_LIMIT){
			vm_stack_growth (fpage_uvaddr);
			fpage = spt_find_page(spt, fpage_uvaddr);
		}
		else{
			exit(-1); // mmap-unmap
			//return false;
		}
	}
	else if(write && !fpage->writable){
		exit(-1); // mmap-ro
		// return false;
	}

	ASSERT(fpage != NULL);

	// Step 2~4.
	bool gotFrame = vm_do_claim_page (fpage);

	if (gotFrame)
		list_push_back(&frame_table, &fpage->frame->elem);

	return gotFrame;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
//
bool
vm_claim_page (void *va UNUSED) {
	// struct page *page = NULL;
	/* TODO: Fill this function */
	// 페이지를 va에 할당해라..

	// 일단 NULL인 페이지 구조체 포인터 하나를 가져왔고
	// 이 페이지를 va에 할당..
	// va를 ..

	// 여기서 할당 준비해서 do_claim으로 보내서 페이지테이블에 맵핑
	// 이 주제의 목적인 supplemental_page_table에서 찾기 구현을 여기서 하면 됨!!
	ASSERT(is_user_vaddr(va)) // 체크용
	struct supplemental_page_table *spt = &thread_current()->spt; // 이러면 주소를 가리키는건가?
	struct page *page = spt_find_page(spt, va);
	if (page == NULL) {
		return false;
	}
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
/* va에서 PT(안의 pa)에 매핑을 추가함. */
//
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
	/* P3 추가 */

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	struct thread *cur = thread_current();
	bool writable = page->writable; // [vm.h] struct page에 bool writable; 추가
	pml4_set_page(cur->pml4, page->va, frame->kva, writable);
	// add the mapping from the virtual address to the physical address in the page table.

	bool res = swap_in (page, frame->kva);

	return res;
}

/* Initialize new supplemental page table */
//
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->spt_hash, page_hash, page_less, NULL);
}
// '추가'페이지 테이블 이니까, 일반 페이지 테이블 init처럼 시작하면 되지 않을까? 근데 일반 페이지테이블 함수는 어디있을깡
// struct page의 union sturct 중 하나를 사용해야 하나?
/* 페이지 폴트 및 리소스 관리를 처리하기 위해 각 페이지에 대한 추가 정보를 보유하는 추가 페이지 테이블도 필요합니다. */
/* 추가 페이지 테이블에 사용할 데이터 구조를 선택할 수 있습니다. -> 비트맵 or 해시테이블 구조로 짜면 된다. */
// 자료형 초깃값, 멤버변수들 넣기. struct도 채워야 함


/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	src->spt_hash.aux = dst; // pass 'dst' as aux to 'hash_apply'
	hash_apply(&src->spt_hash, hash_action_copy);
	return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_destroy(&spt->spt_hash, hash_action_destroy); /* P3 추가 */
}

/* P3 추가 */
// 해시 테이블 초기화할 때 해시 값을 구해주는 함수의 포인터
unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED) {
    const struct page *p = hash_entry(p_, struct page, hash_elem);
    return hash_bytes(&p->va, sizeof p->va);
}

// 해시 테이블 초기화할 때 해시 요소들 비교하는 함수의 포인터
// a가 b보다 작으면 true, 반대면 false
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
    const struct page *a = hash_entry(a_, struct page, hash_elem);
    const struct page *b = hash_entry(b_, struct page, hash_elem);

    return a->va < b->va;
}

/* P3 추가 */
void hash_action_copy (struct hash_elem *e, void *hash_aux) {
	struct thread *t = thread_current();
	ASSERT(&t->spt == (struct supplemental_page_table *)hash_aux); //child's SPT

	struct page *page = hash_entry(e, struct page, hash_elem);
	enum vm_type type = page->operations->type; // type of page to copy

	if(type == VM_UNINIT) {
		struct uninit_page *uninit = &page->uninit;
		vm_initializer *init = uninit->init;
		void *aux = uninit->aux;

		// copy aux (struct lazy_load_info *)
		struct lazy_load_info *lazy_load_info = malloc(sizeof(struct lazy_load_info));
		if(lazy_load_info == NULL) {
			// #ifdef DBG
			// malloc fail - kernel pool all used
		}
		memcpy(lazy_load_info, (struct lazy_load_info *)aux, sizeof(struct lazy_load_info));

		lazy_load_info->file = file_reopen(((struct lazy_load_info *)aux)->file); // get new struct file (calloc)
		vm_alloc_page_with_initializer(uninit->type, page->va, page->writable, init, lazy_load_info);

		// uninit page created by mmap - record page_cnt
		if(uninit->type == VM_FILE) {
			struct page *newpage = spt_find_page(&t->spt, page->va);
			newpage->page_cnt = page->page_cnt;
		}
	}
	if(type & VM_ANON == VM_ANON) { // include stack pages
		// when __do_fork is called, thread_current is the child thread so we can just use vm_alloc_page
		vm_alloc_page(type, page->va, page->writable);

		struct page *newpage = spt_find_page(&t->spt, page->va); // copied page
		vm_do_claim_page(newpage);

		ASSERT(page->frame != NULL);
		memcpy(newpage->frame->kva, page->frame->kva, PGSIZE);
	}
	if(type == VM_FILE) {
		struct lazy_load_info *lazy_load_info = malloc(sizeof(struct lazy_load_info));

		struct file_page *file_page = &page->file;
		lazy_load_info->file = file_reopen(file_page->file);
		lazy_load_info->page_read_bytes = file_page->length;
		lazy_load_info->page_zero_bytes = PGSIZE - file_page->length;
		lazy_load_info->offset = file_page->offset;
		void *aux = lazy_load_info;
		vm_alloc_page_with_initializer(type, page->va, page->writable, lazy_load_segment_for_file, aux);

		struct page *newpage = spt_find_page(&t->spt, page->va); // copied page
		vm_do_claim_page(newpage);

		newpage->page_cnt = page->page_cnt;
		newpage->writable = false;
	}
}

/* P3 추가 */
// same as spt_remove_page except that it doesn't delete the page from SPT hash
// only free page, not frame - just break the page-frame connection 
void remove_page(struct page *page){
	struct thread *t = thread_current();
	pml4_clear_page(t->pml4, page->va);

	if (page->frame != NULL){
		page->frame->page = NULL;
		// list_push_back(&frame_table, &page->frame->elem);
	}
}


void hash_action_destroy (struct hash_elem *e, void *aux){
	struct thread *t = thread_current();
	struct page *page = hash_entry(e, struct page, hash_elem);
	
	// mmap-exit - process exits without calling munmap; unmap here
	if(page->operations->type == VM_FILE){
		if(pml4_is_dirty(t->pml4, page->va)){
			struct file *file = page->file.file;
			size_t length = page->file.length;
			off_t offset = page->file.offset;

			ASSERT(page->frame != NULL);

			if(file_write_at(file, page->frame->kva, length, offset) != length){
			}
		}
	}
	
	if (page->frame != NULL){
		page->frame->page = NULL;		
	}

	remove_page(page);
}