#ifndef _FILESYS_CACHE_
#define _FILESYS_CACHE_

#include "devices/block.h"
#include "lib/kernel/list.h"
#include "lib/kernel/hash.h"

typedef struct cache_entry{
  block_sector_t sector;
  uint8_t* buffer;
  bool writing;
  struct hash_elem elemH;
  struct list_elem elemL;
} cache_entry;

void cache_init();
cache_entry* cache_insert(block_sector_t, bool);
void* lookup_cache(block_sector_t);

#endif