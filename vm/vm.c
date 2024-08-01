/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "lib/kernel/hash.h"
/* ------ Project 3 ------ */
#include <stdio.h>
#include "lib/string.h"
#include "threads/init.h"
#include "threads/pte.h"
#include "threads/mmu.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
/* ----------------------- */

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();

  /* ------ Project 3 ------ */
  list_init (&framelist);
  lock_init (&spt_lock);

#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
  int ty = page->operations->type;
	switch (ty) {
		case VM_UNINIT:
      return page->uninit.type;
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim    (void);
static bool          vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame   (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable, vm_initializer *init, void *aux) {
  ASSERT (VM_TYPE(type) != VM_UNINIT);
  struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
    struct page *n_page = malloc (sizeof(struct page));

    if (writable) {
      upage = (void *)((uint64_t)upage | PTE_W);
    }

    switch (VM_TYPE (type)) {
      case VM_ANON:
        uninit_new (n_page, upage, init, type, aux, anon_initializer);
        break;
      case VM_FILE:
        uninit_new (n_page, upage, init, type, aux, file_backed_initializer);
        break;

      case VM_PAGE_CACHE:
        break;

      default:
        break;
    }

    if (!spt_insert_page(spt, n_page)) {
      return false;
    }
  }
  else {
    return false;
  }

  return true;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
  spt_find_page (struct supplemental_page_table *spt, void *va) {
  struct page *page = page_lookup (va, (void *)&spt->spt_hash);

	return page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt, struct page *page) {
  lock_acquire (&spt_lock);
  bool succ = hash_insert (&spt->spt_hash, &page->h_elem) != NULL ? false : true;
  lock_release (&spt_lock);
  return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
  lock_acquire (&spt_lock);
	vm_dealloc_page (page);
  lock_release (&spt_lock);
  return;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
  struct frame *victim = NULL;

  victim = list_entry (list_front (&framelist), struct frame, f_elem);
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
  struct frame *victim = vm_get_victim ();

  if (!victim) {
    return NULL;
  }

  if (!swap_out (victim->page)) {
    return NULL;
  }

  list_remove (&victim->f_elem);
  victim->page->frame = NULL;
  victim->page = NULL;

  return victim;
}

/*
  palloc() and get frame. This always return valid address.
  If there is no available page, evict the page and return it.
  That is, if the user pool memory is full, this function evicts the frame to get the available memory space.
*/
static struct frame *
vm_get_frame (void) {
  struct frame *frame = (struct frame *)calloc (sizeof(struct frame), 1);
  if (!frame) {
    return NULL;
  }
  frame->kva = palloc_get_page(PAL_USER | PAL_ZERO);

  if (!frame->kva) {
    free (frame);
    frame = vm_evict_frame ();
  }

  list_push_back (&framelist, &frame->f_elem);

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr) {
  void *address = pg_round_down (addr);
  struct supplemental_page_table *spt = &thread_current ()->spt;
  struct page *p = spt_find_page (spt, address);

  while (!p) {
    vm_alloc_page (VM_ANON | IS_STACK, address, true);
    address += PGSIZE;
    p = spt_find_page (spt, address);
  }
}

/*  the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f, void *addr, bool user, bool write, bool not_present) {
  uintptr_t rsp = f->rsp;

  bool addr_in_stack = ((uint64_t)addr >= (rsp - 8)) && (USER_STACK - (uint64_t)addr < (1 << 20));
  if (addr_in_stack) {
    vm_stack_growth (addr);
  }

  return vm_claim_page (addr);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va) {
  struct page *page = spt_find_page (&thread_current()->spt, va);

  if (!page) {
    return false;
  }
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
  struct frame  *frame = vm_get_frame ();
  struct thread     *t = thread_current ();
  void *       uaddr = (void *)((uint64_t)page->va & ~PGMASK);
  void *    writable = (void *)((uint64_t)page->va & PTE_W);

  if (!frame) {
    return false;
  }
	/* Set links */
	frame->page = page;
	page->frame = frame;


  if (!(pml4_get_page (t->pml4, uaddr) == NULL
    && pml4_set_page (t->pml4, uaddr, frame->kva, writable))) {
    return false;
  }

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
  hash_init (&spt->spt_hash, (void *)page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */

static void
hash_page_copy (struct hash_elem *e, void *aux) {
  struct supplemental_page_table *dst = aux;
  struct page            *parent_page = hash_entry(e, struct page, h_elem);
  enum vm_type                vm_type = page_get_type (parent_page);
  uint64_t                   writable = (uint64_t)parent_page & PTE_W;

  switch (parent_page->operations->type) {
    struct page    *child_page;
    file_info      *child_aux;
    void           *child_init;

    case VM_UNINIT:
      child_aux = malloc (sizeof(file_info));

      if (child_aux == NULL) {
        return;
      }
      memcpy (child_aux, parent_page->uninit.aux, sizeof(file_info));
      child_init = parent_page->uninit.init;
      child_page = parent_page->va;

      vm_alloc_page_with_initializer (vm_type, child_page, writable, child_init, child_aux);
      break;

    case VM_ANON:
      vm_alloc_page (vm_type, parent_page->va, writable);
      child_page = spt_find_page (dst, parent_page->va);
      vm_do_claim_page (child_page);
      memcpy (child_page->frame->kva, parent_page->frame->kva, PGSIZE);
      break;

    case VM_FILE:
      vm_alloc_page (vm_type, parent_page->va, writable);
      child_page = spt_find_page (dst, parent_page->va);
      vm_do_claim_page (child_page);
      memcpy (child_page->frame->kva, parent_page->frame->kva, PGSIZE);
      break;

    default:
      break;

  }
}

bool
supplemental_page_table_copy (struct supplemental_page_table *dst, struct supplemental_page_table *src) {
  //* hash table 복제 
  dst->spt_hash.hash = src->spt_hash.hash;
  dst->spt_hash.less = src->spt_hash.less;

  //* 부모의 해시 페이지를 자식의 해시 테이블에 복사 - hash_apply
  src->spt_hash.aux = dst;
  hash_apply (&src->spt_hash, hash_page_copy);

  return true;
}

static void
hash_page_kill (struct hash_elem *e, void *aux) {
  struct page *page = hash_entry (e, struct page, h_elem);
  vm_dealloc_page (page);
}

static void
file_munmap (struct hash_elem *e, void *aux) {
  struct page *page = hash_entry (e, struct page, h_elem);
  enum vm_type type = page->operations->type;

  if (VM_TYPE (type) == VM_FILE) {
    munmap (page->va);
  }
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
  // print_spt ();
  hash_clear (&spt->spt_hash, hash_page_kill);
}

unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
  const struct page *p = hash_entry (p_, struct page, h_elem);
  uint64_t       vaddr = (uint64_t)pg_round_down (p->va);
  return hash_bytes (&vaddr, sizeof p->va);
}

/* Returns true if page a precedes page b. */
bool
page_less (const struct hash_elem *a_,
  const struct hash_elem *b_, void *aux UNUSED) {
  const struct page *a = hash_entry (a_, struct page, h_elem);
  const struct page *b = hash_entry (b_, struct page, h_elem);

  return pg_round_down(a->va) < pg_round_down(b->va);
}

/* Returns the page containing the given virtual address, or a null pointer if no such page exists. */
struct page *
  page_lookup (const void *address, struct supplemental_page_table *spt) {
  struct page       p;
  struct hash_elem *e;

  p.va = (void *)address;
  e = hash_find (&spt->spt_hash, &p.h_elem);
  return e != NULL ? hash_entry (e, struct page, h_elem) : NULL;
}

// ! ------------------------------------ DEBUGGING FUNC ------------------------------------ ! //
void
print_spt(void) {
  struct hash *h = &thread_current()->spt.spt_hash;
  struct hash_iterator i;

  printf ("============= {%s} SUP. PAGE TABLE (%d entries) =============\n", thread_current ()->name, hash_size (h));
  printf ("   USER VA    | KERN VA (PA) |     TYPE     | STK | WRT | DRT(K/U) | OFFSET \n");

  void *va, *kva;
  enum vm_type type;
  char *type_str, *stack_str, *writable_str, *dirty_str, *dirty_k_str, *dirty_u_str;
  file_info *f_info;
  int32_t ofs;
  stack_str = " - ";

  hash_first (&i, h);
  struct page *page;
  uint64_t *pte;
  while (hash_next (&i)) {
    page = hash_entry (hash_cur (&i), struct page, h_elem);

    va = page->va;
    if (page->frame) {
      kva = page->frame->kva;
      // pte = pml4e_walk (thread_current ()->pml4, (uint64_t)page->va, 0);
      writable_str = (uint64_t)page->va & PTE_W ? "YES" : "NO";
      // dirty_str = pml4_is_dirty (thread_current ()->pml4, page->va) ? "YES" : "NO";
      dirty_k_str = pml4_is_dirty (base_pml4, page->frame->kva) ? "YES" : "NO";
      dirty_u_str = pml4_is_dirty (thread_current ()->pml4, page->va) ? "YES" : "NO";
      // dirty_k_str = " - ";
      // dirty_u_str = " - ";
    }
    else {
      kva = NULL;
      dirty_k_str = " - ";
      dirty_u_str = " - ";
    }
    type = page->operations->type;
    if (VM_TYPE(type) == VM_UNINIT) {
      type = page->uninit.type;
      switch (VM_TYPE(type)) {
        case VM_ANON:
          type_str = "UNINIT-ANON";
          break;
        case VM_FILE:
          type_str = "UNINIT-FILE";
          break;
        case VM_PAGE_CACHE:
          type_str = "UNINIT-P.C.";
          break;
        default:
          type_str = "UNKNOWN (#)";
          type_str[9] = VM_TYPE(type) + 48; // 0~7 사이 숫자의 아스키 코드
      }
      // stack_str = (type & IS_STACK) ? "YES" : "NO";
      struct file_page_args *fpargs = (struct file_page_args *)page->uninit.aux;
      writable_str = (uint64_t)page->va & PTE_W ? "(Y)" : "(N)";
    }
    else {
      stack_str = "NO";
      switch (VM_TYPE(type)) {
        case VM_ANON:
          type_str = "ANON";
          // stack_str = page->anon.is_stack ? "YES" : "NO";
          break;
        case VM_FILE:
          type_str = "FILE";
          break;
        case VM_PAGE_CACHE:
          type_str = "PAGE CACHE";
          break;
        default:
          type_str = "UNKNOWN (#)";
          type_str[9] = VM_TYPE(type) + 48; // 0~7 사이 숫자의 아스키 코드
      }
      if (page->uninit.aux) {
        f_info = page->uninit.aux;
        ofs = f_info->ofs;
      }
      else {
        ofs = 0;
      }

    }
    printf (" %12p | %12p | %12s | %3s | %3s |  %3s/%3s | %6d \n",
      pg_round_down (va), kva, type_str, stack_str, writable_str, dirty_k_str, dirty_u_str, ofs);
  }
}