#ifndef _VM_PAGE_H
#define _VM_PAGE_H

#include <stddef.h>
#include "threads/loader.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "lib/kernel/hash.h"

struct lock lock;

typedef struct page_table_entry {
    /* data */
    void* upage;
    void* kpage;

    struct hash_elem elemH;
} page_table_entry;

/* compares 2 frame elements */
static int comp_func_supp_table (struct hash_elem *a, struct hash_elem *b, void *aux){
    struct page_table_entry *aelem = hash_entry(a, page_table_entry, elemH);
    struct page_table_entry *belem = hash_entry(b, page_table_entry, elemH);

    return aelem->kpage > belem->kpage;
}

/* wrapper hash function to hash using upage value */
static unsigned hash_supp_table (const void *elem, size_t size){
    struct page_table_entry *real_elem = hash_entry((struct hash_elem*)elem, page_table_entry, elemH);
    return hash_bytes(real_elem -> upage, size);
}

void supplemental_page_table_init();
void supplemental_page_table_set_frame(struct hash* supplemental_page_table, uint8_t* upage, uint8_t* kpage);
struct page_table_entry* supplemental_page_table_lookup_page(struct hash* supplemental_page_table, uint8_t* upage, uint8_t* kpage);

#endif