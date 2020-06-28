#include "filesys/filesys.h"
#include "cache.h"
#include <debug.h>

#define BUF_SIZE 64
/* cache map */
static struct hash cache_map;

/* list to keep track of last cached file */
static struct list cache_list;

static unsigned hash_cache (const void *elem, void* aux){
    struct cache_entry *real_elem = hash_entry((struct hash_elem*)elem, cache_entry, elemH);

    return hash_bytes(&(real_elem -> sector), sizeof(uint32_t));
}

static int comp_func_cache (struct hash_elem *a, struct hash_elem *b, void *aux){
    struct cache_entry *aelem = hash_entry(a, cache_entry, elemH);
    struct cache_entry *belem = hash_entry(b, cache_entry, elemH);

    return aelem->sector > belem->sector;
}

void cache_init(){
  list_init (&cache_list);
  hash_init (&cache_map, hash_cache, comp_func_cache, NULL);
}

/* look up sector in cache and if found move it to the
  back of the list for LRU caching */
void* lookup_cache(block_sector_t sector){
  cache_entry cache;
  cache.sector = sector;
  struct hash_elem* el = hash_find(&cache_map, &(cache.elemH));
  
  if(el != NULL) {
    cache_entry *temp = hash_entry(el, cache_entry, elemH);
    list_remove(&(temp -> elemL));
    list_push_back(&cache_list, &(temp -> elemL));

    return temp;
  }
  return NULL;
}

/* evicting sector in case cache is full */
void cache_evict(){
  struct list_elem *e;
  for (e = list_begin (&cache_list); e != list_end (&cache_list); e = list_next (e)){
    cache_entry* entry = list_entry(e, struct cache_entry, elemL);
    
    if(entry -> writing){
      block_write (fs_device, entry->sector, entry->buffer);
      list_remove(&entry->elemL);
      hash_delete(&cache_map, &entry->elemH);

      free(entry -> buffer);
      free(entry);
      break;
    }
  }

}

/* inserting new sector to cache */
cache_entry* cache_insert(block_sector_t sector_idx, bool writing){
  if(list_size(&cache_list) == BUF_SIZE){
    cache_evict();
  } 
  cache_entry* cache = malloc(sizeof(cache_entry));
  ASSERT(cache != NULL);
  cache->buffer = malloc(BLOCK_SECTOR_SIZE);
  ASSERT(cache->buffer != NULL);

  cache->sector = sector_idx;
  cache->writing = writing;

  hash_insert(&cache_map, &(cache->elemH));
  list_push_back(&cache_list, &(cache->elemL));
  return cache;
}

void dispose_cache(){
  struct list_elem *e;
  for (e = list_begin (&cache_list); e != list_end (&cache_list); e = list_next (e)){
    cache_entry* entry = list_entry(e, struct cache_entry, elemL);
    if(entry -> writing){
      block_write (fs_device, entry->sector, entry->buffer);
    }
  }
}
