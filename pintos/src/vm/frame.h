#ifndef _VM_FRAME_H
#define _VM_FRAME_H

#include <stddef.h>
#include "lib/stdint.h"
#include "threads/palloc.h"

struct frame {
    uint8_t *upage;
    uint8_t *kpage;
    struct thread *pr;
    struct list_elem elemL;
    struct hash_elem elemH;
    bool pinned;
};

void frame_init (size_t);
uint8_t *frame_get_page(enum palloc_flags, uint8_t *);
void frame_free_page (void *);
struct frame* get_frame(void*);
void set_pinned(void *, size_t, bool);
void delete_thread_frames(struct thread* t);
#endif