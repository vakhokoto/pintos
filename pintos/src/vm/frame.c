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

struct frame{
    uint8_t* upage;
    void* kpage;
    struct list_elem elemL;
    struct hash_elem elemH; 
};

static struct list elems;
static struct lock lock;
static struct hash map;

void frame_init (){
    list_init(&elems);
    lock_init(&lock);
}

void *frame_get_page (enum palloc_flags flags, uint8_t* upage){
    lock_acquire(&lock);
    void* addr = palloc_get_page(PAL_USER);
    if(addr == NULL){
        //eviction
    } else {
        struct frame fr;
        fr.kpage = addr;
        fr.upage = upage;
        list_push_back(&elems, &(fr.elemL));
    }
    lock_release(&lock);
}

void frame_free_page (void * page){

}
