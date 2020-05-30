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

struct frame {
    uint8_t *upage;
    uint8_t *kpage;
    struct list_elem elemL;
    struct hash_elem elemH;
};

static struct list elems;
static struct lock lock;
static struct hash map;

/* evicts frame and returns 0 else != 0 number */
int evict_frame(void);

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
   // printf("-------------------------init-------------------------\n");
    list_init(&elems);
    lock_init(&lock);
    hash_init(&map, my_hash, comp_func_bytes, NULL);
}

void *frame_get_page(enum palloc_flags flags, uint8_t* upage){
    lock_acquire(&lock);
    //printf("FRAME-GETTING PAGE\n");

    void* addr = palloc_get_page(flags);
    if(addr == NULL){
        evict_frame();
    } else {
        struct frame *fr = malloc(sizeof(struct frame));
        fr -> kpage = addr;
        fr -> upage = upage;
        list_push_back(&elems, &(fr -> elemL));
        hash_insert(&map, &(fr -> elemH));
    }

    lock_release(&lock);

    return addr;
}

int evict_frame(void){
    // TODO
}

void frame_free_page (void *upage){
    lock_acquire(&lock);


    //printf("FRAME-Freeing PAGE\n");

    struct frame temp_frame;
    temp_frame.upage = upage;
    temp_frame.kpage = NULL;

    struct hash_elem *found_elem = hash_find(&map, &temp_frame.elemH);
    
    if (found_elem != NULL){
        struct frame *felem = hash_entry(found_elem, struct frame, elemH);

        list_remove(&felem -> elemL);
        hash_delete(&map, found_elem);
        palloc_free_page(felem -> kpage);
    }
    
    lock_release(&lock);
}
