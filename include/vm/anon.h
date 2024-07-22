#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"
struct page;
enum vm_type;

struct anon_page {
    int swap_sec; // sector where swapped contents are stored 
};

void vm_anon_init (void);
bool anon_initializer (struct page *page, enum vm_type type, void *kva);

struct bitmap *swap_table; // 0 - empty, 1 - filled
int bitcnt;

#endif
