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

/* init Supplemental Page Table for process */ 
void supplemental_page_table_init(struct hash* supplemental_page_table) {
    lock_init(&lock);
    hash_init(supplemental_page_table, hash_supp_table, comp_func_supp_table, NULL);
}

/* Returns Kernel Page entry according to the User Page */
struct page_table_entry* supplemental_page_table_lookup_page(struct hash* supplemental_page_table, uint8_t* upage) {
    lock_acquire(&lock);
    
    page_table_entry* pte = malloc(sizeof(page_table_entry));
    pte->upage = upage;

    struct page_table_entry* find = NULL;
    struct hash_elem* elem = hash_find(supplemental_page_table, &(pte->elemH));
    if(elem) find = hash_entry(elem, struct page_table_entry, elemH);
    lock_release(&lock);
    return find;
}

/* Sets User page into Supplemental Page Table */
bool supplemental_page_table_set_frame(struct hash* supplemental_page_table, uint8_t* upage, uint8_t* kpage) {
    ASSERT(supplemental_page_table != NULL);
    lock_acquire(&lock);
    bool success = true;

    page_table_entry* new = malloc(sizeof(page_table_entry));
    new->upage = upage;
    new->kpage = kpage;

    struct hash_elem* old = hash_insert(supplemental_page_table, new); 
    
    /* already added */
    if(old) {
        free(new);
        success = false;
    }
    lock_release(&lock);
    return success;
}

/* Removes User page from Supplemental Page Table */
void supplemental_page_table_clear_frame (struct hash* supplemental_page_table, uint8_t *upage){
    lock_acquire(&lock);
    
    page_table_entry* pte = malloc(sizeof(page_table_entry));
    pte->upage = upage;

    struct page_table_entry* find;
    struct hash_elem* elem = hash_find(supplemental_page_table, pte);
    if(elem) {
        find = hash_entry(elem, struct page_table_entry, elemH);
        hash_delete(supplemental_page_table, &(find->elemH));
    }
    lock_release(&lock);
}

/* Mapps File offset into tha Supplemental Page Table - call from Syscall SYS_MMAP */
bool supplemental_page_table_can_map_file(struct hash* supplemental_page_table, uint8_t* upage, file_info_t* file_info) {
    size_t i;
    for(i = 0; i*PGSIZE < file_info->size; i++) {
      if(supplemental_page_table_lookup_page(&(thread_current()->supp_table), upage + i*PGSIZE))
        return false;
    }
    return true;
}

/* Mapps File offset into tha Supplemental Page Table - call from Syscall SYS_MMAP */
void supplemental_page_table_map_file(struct hash* supplemental_page_table, mmap_info_t* mmap_info) {
    size_t i;
    for(i = 0; i*PGSIZE < mmap_info->file_info->size; i++) {
        //TODO

    }
}

/* Unmapps File offset into tha Supplemental Page Table - call from Syscall SYS_MUNMMAP */
void supplemental_page_table_unmap_file(struct hash* supplemental_page_table, mmap_info_t* mmap_info) {
    size_t i;
    for(i = 0; i*PGSIZE < mmap_info->file_info->size; i++) {
        //TODO
        
    }
}


/* destroy Supplemental Page Table */
void supplemental_page_table_destroy(struct hash* supplemental_page_table) {
    ASSERT(supplemental_page_table != NULL);
    hash_destroy(supplemental_page_table, NULL);
}