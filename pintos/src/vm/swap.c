#include "vm/swap.h"
#include "vm/frame.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "lib/stdint.h"
#include "lib/kernel/bitmap.h"
#include "threads/vaddr.h"
#include "lib/stdbool.h"
#include "vm/page.h"

/* swap block */
static struct block *swap_block;

/* map of pages to sign which is free */
static struct bitmap *map;

/* number of sectors per page */
static const size_t SECTORS_PER_PAGE = PGSIZE / BLOCK_SECTOR_SIZE;

/* count of bits in bitmap */
static block_sector_t bcount;

/* lock to access swap */
static struct lock swap_access_lock;

/* initializes the swap block */
void swap_init(){
    // შეიძლება ჯიდევ უნდა დამატებით შემოწმებები და დღეს დავამატებ

    swap_block = block_get_role(BLOCK_SWAP);
    lock_init(&swap_access_lock);
    bcount = block_size(swap_block);
    map = bitmap_create(bcount);
}

/* function to add page to ram and returns position
    starting from which the page is written  and returns -1 in case 
    there is no place for page and entire swap is full */
swap_idx_t swap_add(void *kpage){
    ASSERT (kpage != NULL);
    // შეიძლება ჯიდევ უნდა დამატებით შემოწმებები და დღეს დავამატებ
    
    lock_acquire(&swap_access_lock);

    swap_idx_t idx = bitmap_scan(map, 0, SECTORS_PER_PAGE, false);

    if (idx == BITMAP_ERROR){
        lock_release(&swap_access_lock);
        return -1;
    }

    swap_idx_t i;
    for (i = idx; i < idx + SECTORS_PER_PAGE; i++){
        bitmap_mark(map, i);
        kpage += BLOCK_SECTOR_SIZE;
        block_write(swap_block, i, kpage);
    }

    lock_release(&swap_access_lock);

    return idx;
}

/* function to get page with the index from swap */
uint8_t* swap_get(swap_idx_t idx){
    void* kpage = malloc(SECTORS_PER_PAGE);
    ASSERT(idx >= 0 && idx <= bcount - SECTORS_PER_PAGE);
    // შეიძლება ჯიდევ უნდა დამატებით შემოწმებები და დღეს დავამატებ

    lock_acquire(&swap_access_lock);

    swap_idx_t i;
    for (i = idx; i < idx + SECTORS_PER_PAGE; i++){
        kpage += BLOCK_SECTOR_SIZE;
        block_read(swap_block, i, kpage);
    }

    lock_release(&swap_access_lock);
    return (uint8_t*)kpage;
}

/* function to free and remove page from swap */
void swap_free(swap_idx_t idx){
    ASSERT(idx >= 0 && idx <= bcount - SECTORS_PER_PAGE);
    // შეიძლება ჯიდევ უნდა დამატებით შემოწმებები და დღეს დავამატებ
    
    lock_acquire(&swap_access_lock);

    bitmap_set_multiple(map, idx, SECTORS_PER_PAGE, false);

    lock_release(&swap_access_lock);
}

swap_idx_t get_swap_idx(struct hash* swap_table, uint8_t* upage) {
    lock_acquire(&swap_access_lock);
    
    swap_table_entry* ste = malloc(sizeof(swap_table_entry));
    ste->upage = upage;

    struct swap_table_entry* find;
    struct hash_elem* elem = hash_find(swap_table, ste);
    if(elem) find = hash_entry(elem, struct swap_table_entry, elemH);
    lock_release(&swap_access_lock);
    return find->idx;
}


/**Swap Table*/

 void swap_table_init(struct hash* swap_table){
    hash_init(swap_table, hash_swap_table, comp_func_swap_table, NULL);
 }

