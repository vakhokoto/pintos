#ifndef _VM_SWAP_H
#define _VM_SWAP_H

#include <stddef.h>
#include <stdio.h>
#include "lib/kernel/hash.h"
typedef size_t swap_idx_t;


typedef struct swap_table_entry{
    swap_idx_t idx;
    uint8_t* upage;
    struct hash_elem elemH;
} swap_table_entry;

/* initializes the swap block */
void swap_init();

/* function to add page to ram */
swap_idx_t swap_add(void *);

/* function to get page with the index from swap */
void swap_get(swap_idx_t idx, void* kpage);

/* function to free and remove page from swap */
void swap_free(swap_idx_t);

void swap_table_init(struct hash* swap_table);

static unsigned hash_swap_table (const void *elem, size_t size){
    struct swap_table_entry *real_elem = hash_entry((struct hash_elem*)elem, swap_table_entry, elemH);
    return hash_bytes(&(real_elem -> upage), size);
}

static int comp_func_swap_table (struct hash_elem *a, struct hash_elem *b, void *aux){
    struct swap_table_entry *aelem = hash_entry(a, swap_table_entry, elemH);
    struct swap_table_entry *belem = hash_entry(b, swap_table_entry, elemH);

    return aelem->idx > belem->idx;
}

swap_idx_t get_swap_idx(struct hash* swap_table, uint8_t* upage);

#endif