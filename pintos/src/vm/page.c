#include "page.h"
#include "threads/palloc.h"
#include <bitmap.h>
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "threads/loader.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "lib/kernel/hash.h"

void supplemental_page_table_init() {
    lock_init(&lock);
}

struct page_table_entry* supplemental_page_table_lookup_page(struct hash* supplemental_page_table, uint8_t* upage, uint8_t* kpage) {
    lock_acquire(&lock);
    
    page_table_entry* pte = malloc(sizeof(page_table_entry));
    pte->upage = upage;
    pte->kpage = kpage;

    struct page_table_entry* find;
    struct hash_elem* elem = hash_find(supplemental_page_table, pte);
    if(elem) hash_entry(elem, struct page_table_entry, elemH);
    lock_release(&lock);
    return find;
}

void supplemental_page_table_set_frame(struct hash* supplemental_page_table, uint8_t* upage, uint8_t* kpage) {
    lock_acquire(&lock);
    
    page_table_entry* new = malloc(sizeof(page_table_entry));
    new->upage = upage;
    new->kpage = kpage;

    struct hash_elem* old = hash_insert(supplemental_page_table, new); 
    
    /* already added */
    if(old) free(new);

    lock_release(&lock);
}