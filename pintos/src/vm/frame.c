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
#include "threads/thread.h"
#include "lib/kernel/hash.h"
#include "vm/swap.h"
#include "vm/page.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"

struct frame {
    uint8_t *upage;
    uint8_t *kpage;
    struct thread *pr;
    struct list_elem elemL;
    struct hash_elem elemH;
};

static struct list elems;  // frame list
static struct lock flock;
static struct hash map;

/* evicts frame and returns 0 else != 0 number */
uint8_t* evict_frame(enum palloc_flags flags, uint8_t* upage);

struct frame* pick_frame_to_evict();

/* compares 2 frame elements */
int comp_func_bytes(struct hash_elem *a, struct hash_elem *b, void *aux){
    struct frame *aelem = hash_entry(a, struct frame, elemH);
    struct frame *belem = hash_entry(b, struct frame, elemH);

    return aelem -> kpage > belem -> kpage;
}

/* wrapper hash function to hash using upage value */
unsigned my_hash (const void *elem, size_t size){
    struct frame *real_elem = hash_entry((struct hash_elem*)elem, struct frame, elemH);

    return hash_bytes(real_elem -> upage, size);
}

void frame_init (size_t user_page_limit){
    list_init(&elems);
    lock_init(&flock);
    hash_init(&map, my_hash, comp_func_bytes, NULL);
	// printf("frame:\n\tframe inited\n");
}

uint8_t *frame_get_page(enum palloc_flags flags, uint8_t* upage){
    // printf("frame:\n\tpage creating to -> %d %p\n", flags, upage);

    uint8_t* addr = palloc_get_page(flags);
    if(addr == NULL){
        addr = evict_frame(flags, upage);
        // printf("\tevicted -> %p\n", addr);
    } else {
        struct frame *fr = malloc(sizeof(struct frame));

        fr -> kpage = addr;
        fr -> upage = upage;
        fr -> pr = thread_current();
        lock_acquire(&flock);
        list_push_back(&elems, &(fr -> elemL));
        hash_insert(&map, &(fr -> elemH));  
        lock_release(&flock);
        // printf("\tnot evicted\n");
    }

    supplemental_page_table_set_frame(&(thread_current()->supp_table), upage, addr);
    // printf("\taddress associated -> %p\n", addr);
    return addr;
}

/** Evicts */
uint8_t* evict_frame(enum palloc_flags flags, uint8_t* upage){
  
	// printf("frame:\n\tevicting frame for -> %d %p\n", flags, upage);
    struct frame* to_evict = pick_frame_to_evict();

    swap_idx_t idx = swap_add(to_evict->kpage);

    swap_table_entry* entry = malloc(sizeof(swap_table_entry));
    entry->upage = to_evict->upage;
    entry->idx = idx;

    hash_insert(&(to_evict->pr->swap_table),  &(entry->elemH));
    // TODO DIRTY BITS THING
    pagedir_clear_page(to_evict->pr->pagedir, to_evict->upage);
    palloc_free_page(to_evict->kpage);
      
    uint8_t* frame_page = (uint8_t*)palloc_get_page(flags);
    ASSERT(frame_page != NULL);
    struct frame* new = malloc(sizeof(struct frame));
	new->pr = thread_current();
	new->upage = upage;
	new->kpage = frame_page;
    list_push_back(&elems, &(new -> elemL));
    hash_insert(&map, &(new -> elemH));
	// printf("\tevicted address ker | user -> %p %p\n", to_evict -> kpage, to_evict -> upage);
 //   pagedir_set_page(thread_current()->pagedir, upage, frame_page, true);

    return frame_page;
}

/** Find the frame to be evicted
 *  Currently uses FIFO algorithm
 *  TODO LRU
*/
struct frame* pick_frame_to_evict(){
    // FIFO ALGORITHM NEEDS TO CHANGE
    struct list_elem *tempL = list_pop_front(&elems);

    struct frame *temp = list_entry(tempL, struct frame, elemL);
    while(pagedir_is_dirty(temp->pr->pagedir, temp->upage) || pagedir_is_accessed(temp->pr->pagedir, temp->upage)){
        list_push_back(&elems, &(temp->elemL));
        tempL = list_pop_front(&elems);
        temp = list_entry(tempL, struct frame, elemL);
        if (pagedir_is_accessed(temp->pr->pagedir, temp->upage)) {
            pagedir_set_accessed(temp->pr->pagedir, temp->upage, false);
		}
    }
    hash_delete(&map, &(temp->elemH));
    return temp;
}

void frame_free_page (void *upage){
   // NO synchronization necessary for 

	// printf("frame:\n\tfreeing page -> %p\n", upage);
    struct frame temp_frame;
    temp_frame.upage = upage;
    temp_frame.kpage = NULL;

    struct hash_elem *found_elem = hash_find(&map, &temp_frame.elemH);
    
    if (found_elem != NULL){
        struct frame *felem = hash_entry(found_elem, struct frame, elemH);

        list_remove(&felem -> elemL);
        hash_delete(&map, found_elem);
        palloc_free_page(felem -> kpage);
		// printf("\tfreeed\n");
    } else {
		// printf("\tno page to free\n");
	}
}
