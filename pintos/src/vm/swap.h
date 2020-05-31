#ifndef _VM_SWAP
#define _VM_SWAP

typedef size_t swap_idx_t;

/* initializes the swap block */
void swap_init();

/* function to add page to ram */
swap_idx_t swap_add(void *);

/* function to get page with the index from swap */
void swap_get(swap_idx_t, void *);

/* function to free and remove page from swap */
void swap_free(swap_idx_t);

#endif