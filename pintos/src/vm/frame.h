#ifndef _VM_FRAME_H
#define _VM_FRAME_H

#include <stddef.h>
#include "threads/palloc.h"

void frame_init (size_t user_page_limit);
void *frame_get_page(enum palloc_flags flags, uint8_t* upage);
void frame_free_page (void * upage);

#endif