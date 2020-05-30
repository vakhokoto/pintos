#include "vm/swap.h"
#include "vm/frame.h"
#include "devices/block.h"
#include "threads/synch.h"

/* swap block */
static struct block *swap_block;

/* lock to access swap */
static struct lock swap_access_lock;

/* initializes the swap block */
void swap_init(){
    swap_block = block_get_role(BLOCK_SWAP);
    lock_init(&swap_access_lock);
}

/* function to add page to ram */
swap_idx_t swap_add(void *kpage){
    
}

/* function to get page with the index from swap */
void swap_get(swap_idx_t idx, void *kpage){

}

/* function to free and remove page from swap */
void swap_free(swap_idx_t idx){

}