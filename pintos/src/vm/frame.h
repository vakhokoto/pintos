#include <stddef.h>
#include <palloc.h>

void frame_init (size_t user_page_limit);
void *frame_get_page (enum palloc_flags);
void frame_free_page (void *);