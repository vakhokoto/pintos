#include "page.h"
#include "frame.h"
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
#include "userprog/pagedir.h"

/* init Supplemental Page Table for process */ 
void supplemental_page_table_init(struct hash* supplemental_page_table) {
    lock_init(&lock);
    hash_init(supplemental_page_table, hash_supp_table, comp_func_supp_table, NULL);
}

/* Returns Kernel Page entry according to the User Page */
struct page_table_entry* supplemental_page_table_lookup_page(struct hash* supplemental_page_table, uint8_t* upage) {
    bool ind  = false;
    if (!lock_held_by_current_thread(&lock)){
        ind = true;
        lock_acquire(&lock);
    }
    
    page_table_entry* pte = malloc(sizeof(page_table_entry));
    pte->upage = upage;

    struct page_table_entry* find = NULL;
    struct hash_elem* elem = hash_find(supplemental_page_table, &(pte->elemH));
    if(elem != NULL) find = hash_entry(elem, struct page_table_entry, elemH);
    
    free(pte);
    if (ind)
        lock_release(&lock);
    return find;
}

/* Sets User page into Supplemental Page Table */
bool supplemental_page_table_set_frame(struct hash* supplemental_page_table, uint8_t* upage, uint8_t* kpage) {
    ASSERT(supplemental_page_table != NULL);
    bool ind  = false;
    if (!lock_held_by_current_thread(&lock)){
        ind = true;
        lock_acquire(&lock);
    }

    page_table_entry* new = malloc(sizeof(page_table_entry));
    new->upage = upage;
    new->kpage = kpage;
    struct hash_elem* old = hash_insert(supplemental_page_table, &(new->elemH)); 
    
    /* already added */
    if(old != NULL) {
        hash_replace(supplemental_page_table, &(new->elemH));
    }

    if (ind)
        lock_release(&lock);
    return true;
}

/* Removes User page from Supplemental Page Table */
void supplemental_page_table_clear_frame (struct hash* supplemental_page_table, uint8_t *upage){
    bool ind  = false;
    if (!lock_held_by_current_thread(&lock)){
        ind = true;
        lock_acquire(&lock);
    }
    
    page_table_entry pte;
    pte.upage = upage;

    struct page_table_entry* find;
    struct hash_elem* elem = hash_find(supplemental_page_table, &(pte.elemH));
    if(elem != NULL) {
        find = hash_entry(elem, struct page_table_entry, elemH);
        hash_delete(supplemental_page_table, &(find->elemH));
    }

    if (ind)
        lock_release(&lock);
}

void debug(struct hash_elem* he) {
    page_table_entry* pte = hash_entry(he, struct page_table_entry, elemH);
    printf("hash elem -> upage %p, kpage %p \n", pte->upage, pte->kpage);
}

bool supplemental_page_table_try_map_file(struct hash* supplemental_page_table, mmap_info_t* mmap_info) {
    lock_acquire(&lock);

    size_t i;
    for(i = 0; i*PGSIZE < mmap_info->file_info->size; i++) {
        page_table_entry* pte = malloc(sizeof(page_table_entry));
        pte->upage = mmap_info->upage + i*PGSIZE;

        struct page_table_entry* find = NULL;
        struct hash_elem* elem = hash_find(supplemental_page_table, &(pte->elemH));
        if(elem != NULL) find = hash_entry(elem, struct page_table_entry, elemH);
        free(pte);

        if(find || !is_user_vaddr(mmap_info->upage + i*PGSIZE)){
            lock_release(&lock);
            return false;
        }
    }
    
    for(i = 0; i*PGSIZE < mmap_info->file_info->size; i++) {
        page_table_entry* pte = malloc(sizeof(page_table_entry));
        pte->upage = mmap_info->upage + i*PGSIZE;
        pte->kpage = NULL;
        supplemental_page_table_set_frame(&(thread_current()->supp_table), pte->upage, pte->kpage);

        memset(pte->upage, 0, PGSIZE);
        struct frame* fr = get_frame(pte->upage);
        ASSERT(fr != NULL);
        fr->pinned = true;
        size_t tot = file_read(mmap_info->file_info->file, pte->upage, PGSIZE);
        fr->pinned = false;
    }
    mmap_info->upage_modify = malloc(mmap_info->file_info->size);
    memcpy(mmap_info->upage_modify, mmap_info->upage, mmap_info->file_info->size);
    lock_release(&lock);
    return true;
}

/* Mapps File offset into tha Supplemental Page Table - call from Syscall SYS_MMAP */
bool supplemental_page_table_can_map_file(struct hash* supplemental_page_table, uint8_t* upage, file_info_t* file_info) {
    bool ind  = false;
    if (!lock_held_by_current_thread(&lock)){
        ind = true;
        lock_acquire(&lock);
    }

    size_t i;
    for(i = 0; i*PGSIZE < file_info->size; i++) { // think about <=
        page_table_entry* entry = supplemental_page_table_lookup_page(&(thread_current()->supp_table), upage + i*PGSIZE);
        if(entry || !is_user_vaddr(upage + i*PGSIZE)){
            // safe unlock
            if (ind)
                lock_release(&lock);

            return false;
        }
    }

    if (ind)
        lock_release(&lock);
    return true;
}

/* Mapps File offset into tha Supplemental Page Table - call from Syscall SYS_MMAP */
void supplemental_page_table_map_file(struct hash* supplemental_page_table, mmap_info_t* mmap_info) {
    bool ind  = false;
    if (!lock_held_by_current_thread(&lock)){
        ind = true;
        lock_acquire(&lock);
    }

    size_t i;
    for(i = 0; i*PGSIZE < mmap_info->file_info->size; i++) { // think about <=
        page_table_entry* pte = malloc(sizeof(page_table_entry));
        pte->upage = mmap_info->upage + i*PGSIZE;
        pte->kpage = frame_get_page(PAL_USER, pte->upage);
        struct hash_elem* old = hash_insert(supplemental_page_table, &(pte->elemH));
        ASSERT(old == NULL);
    }

    if (ind)
        lock_release(&lock);
}

/* Unmapps File offset into tha Supplemental Page Table - call from Syscall SYS_MUNMMAP */
void supplemental_page_table_unmap_file(struct hash* supplemental_page_table, mmap_info_t* mmap_info) {
    bool ind  = false;
    if (!lock_held_by_current_thread(&lock)){
        ind = true;
        lock_acquire(&lock);
    }
    size_t i;
    for(i = 0; i*PGSIZE < mmap_info->file_info->size; i++) { // think about <=
        page_table_entry* pte = supplemental_page_table_lookup_page(&(thread_current()->supp_table), mmap_info->upage + i*PGSIZE);
        ASSERT(pte != NULL);
        pagedir_clear_page(thread_current() -> pagedir, mmap_info->upage + i*PGSIZE);

        // deleting from suppp page table
        hash_delete(supplemental_page_table, &(pte->elemH));

        free(pte);
    }

    if (ind)
        lock_release(&lock);
}

/* destroy Page Table ENtry */
void page_table_entry_destroy(page_table_entry* pte) {
    free(pte);
}

/* destroy Supplemental Page Table */
void supplemental_page_table_destroy(struct hash* supplemental_page_table) {
    ASSERT(supplemental_page_table != NULL);

    bool ind  = false;
    if (!lock_held_by_current_thread(&lock)){
        ind = true;
        lock_acquire(&lock);
    }
    
    hash_destroy(supplemental_page_table, page_table_entry_destroy);

    if (ind)
        lock_release(&lock);
}