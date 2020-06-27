#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "lib/kernel/hash.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define BUF_SIZE 64
#define MAX_FILE_SIZE 16636
#define DIRECT_SIZE 124
#define SINGLE_SIZE 128
#define ON_SINGLE_SECTOR 128
#define DOUBLE_SIZE 128 * 128

/* cache map */
static struct hash cache_map;

/* list to keep track of last cached file */
static struct list cache_list;

/* lock for cache access */
struct lock cache_lock;

typedef struct cache_entry{
  block_sector_t sector;
  uint8_t* buffer;
  bool writing;
  struct hash_elem elemH;
  struct list_elem elemL;
} cache_entry;

static unsigned hash_cache (const void *elem, void* aux){
    struct cache_entry *real_elem = hash_entry((struct hash_elem*)elem, cache_entry, elemH);

    return hash_bytes(&(real_elem -> sector), sizeof(uint32_t));
}

static int comp_func_cache (struct hash_elem *a, struct hash_elem *b, void *aux){
    struct cache_entry *aelem = hash_entry(a, cache_entry, elemH);
    struct cache_entry *belem = hash_entry(b, cache_entry, elemH);

    return aelem->sector > belem->sector;
}

void* lookup_cache(struct hash* map, block_sector_t sector){
  cache_entry cache;
  cache.sector = sector;
  struct hash_elem* el = hash_find(map, &(cache.elemH));
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

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t directs[124];
    block_sector_t single_indirect;
    block_sector_t double_indirect;
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos)
{
  ASSERT (inode != NULL);
  block_sector_t* tempo = malloc(BLOCK_SECTOR_SIZE);
  if (pos < BLOCK_SECTOR_SIZE * MAX_FILE_SIZE){
    block_sector_t res;
    if(pos >= 252 * BLOCK_SECTOR_SIZE){
      off_t new_pos = pos / BLOCK_SECTOR_SIZE - 252;
      off_t double_pos = new_pos / 128;
      off_t ind_pos = new_pos % 128;
      block_read(fs_device, inode->data.double_indirect, tempo);
      block_read(fs_device, tempo[double_pos], tempo);
      res = tempo[ind_pos];
    } else if(pos >= 124 * BLOCK_SECTOR_SIZE){
      block_read(fs_device, inode->data.single_indirect, tempo);
      res = tempo[pos / BLOCK_SECTOR_SIZE - 124];
    } else {
      res = inode->data.directs[pos / BLOCK_SECTOR_SIZE];
    }
    free(tempo);
    return res;
  } else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void)
{
  list_init (&open_inodes);
  list_init (&cache_list);
  hash_init (&cache_map, hash_cache, comp_func_cache, NULL);
  lock_init (&cache_lock);
}

/* creates direct blocks for new files and fills it with 0s */
bool inode_create_direct(struct inode_disk *dsk, size_t num_alloc){
  // printf("-------------direct-------------\n");
  /* fill in with 0s for on default */
  memset(dsk -> directs, 0, DIRECT_SIZE * sizeof(block_sector_t));
  
  bool res = true;

  int i;
  for (i = 0; i < num_alloc; ++i){
    res &= free_map_allocate(1, &dsk -> directs[i]);
    if (!res)
      return res;
  }

  // printf("-------------direct--ended-------------\n");
  return res;
}

/* in case file needs more than DIRECT_SIZE sectors 
  single indirect part should be added */
bool inode_create_single(struct inode_disk *dsk, size_t num_alloc){
  // printf("------------------single------------------\n");
  free_map_allocate(1, &dsk->single_indirect);

  block_sector_t buf[ON_SINGLE_SECTOR];
  memset(buf, 0, ON_SINGLE_SECTOR * sizeof(block_sector_t));

  bool res = true;

  size_t i;
  for (i = 0; i < num_alloc; i++){
    res &= free_map_allocate(1, &buf[i]);
  }
  block_write(fs_device, dsk -> single_indirect, buf);

  // printf("------------------single--ended------------------\n");
  return res;
}

/* and in case new file siz is more thant DIRECT_SIZE + SINGLE_SIZE 
  than we need double indirect sectors */
bool inode_create_double(struct inode_disk *dsk, size_t num_alloc){
  // printf("-------------double-------------\n");
  size_t counter = num_alloc;
  size_t top_level = num_alloc / ON_SINGLE_SECTOR + (num_alloc % ON_SINGLE_SECTOR > 0 ?1:0);

  free_map_allocate(1, &dsk->double_indirect);
  block_sector_t d_buf[ON_SINGLE_SECTOR];
  memset(d_buf, 0, ON_SINGLE_SECTOR * sizeof(block_sector_t));

  bool res = true;

  int i;
  for  (i = 0; i < top_level; i++){
    res &= free_map_allocate(1, d_buf[i]);

    block_sector_t buf[ON_SINGLE_SECTOR];
    memset(buf, 0, ON_SINGLE_SECTOR * sizeof(block_sector_t));

    int j;
    for (j = 0; j<min(ON_SINGLE_SECTOR, counter); j++){
      res &= free_map_allocate(1, &buf[j]);
      
      if (!res)
        return res;
    }
    block_write(fs_device, d_buf[i], buf);

    counter -= min(counter, ON_SINGLE_SECTOR);
  }

  block_write(fs_device, dsk -> double_indirect, d_buf);

  // printf("-------------double---ended-------------\n");
  return res;
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  // printf("--------------creating--------------\n");
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      if(free_map_free_space() > sectors){
        
        if (sectors > 0) {
          success = true;
          success &= inode_create_direct(disk_inode, min(sectors, DIRECT_SIZE));
          sectors -= min(sectors, DIRECT_SIZE);
        } else {
          success = true;
        }

        if (sectors > 0){
          success &= inode_create_single(disk_inode, min(sectors, SINGLE_SIZE));
          sectors -= min(SINGLE_SIZE, sectors);
        }

        if (sectors > 0){
          success &= inode_create_double(disk_inode, min(sectors, DOUBLE_SIZE));
        }
        block_write (fs_device, sector, disk_inode);
        free (disk_inode);
      }    
    }

  // printf("--------------creating---ended--------------\n");
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e))
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector)
        {
          inode_reopen (inode);
          return inode;
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  // inode_read_at(inode, &inode->data, BLOCK_SECTOR_SIZE, 0);
  block_read (fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode)
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);

      /* Deallocate blocks if removed. */
      if (inode->removed)
        {
          free_map_release (inode->sector, 1);
        }

      free (inode);
    }
}

void delete_sectors(block_sector_t* blocks, off_t till){
  int i = 0;
  for(; i < till; i++){
    free_map_release(blocks[i], 1);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode)
{
  ASSERT (inode != NULL);
  inode->removed = true;
  int total = bytes_to_sectors(inode->data.length);
  block_sector_t* mass = malloc(sizeof(block_sector_t));
  block_sector_t* tempo = malloc(sizeof(block_sector_t));
  int i = 0;
  if(total > DIRECT_SIZE + ON_SINGLE_SECTOR){
    off_t new_pos = i - 252 - 1;
    off_t double_pos = new_pos / ON_SINGLE_SECTOR;
    off_t ind_pos = new_pos % ON_SINGLE_SECTOR;
    block_read(fs_device, inode->data.double_indirect, mass);
    
    for(; i < double_pos - 1; i++){
      block_read(fs_device, mass[i], tempo);
      delete_sectors(tempo, ON_SINGLE_SECTOR);
    }
    block_read(fs_device, mass[double_pos], tempo);
    
    delete_sectors(tempo, ind_pos);
    delete_sectors(mass, ON_SINGLE_SECTOR);
    free_map_release(inode->data.double_indirect, 1);
  }
  if(total > DIRECT_SIZE){
    block_read(fs_device, inode->data.single_indirect, mass);
    delete_sectors(mass, ON_SINGLE_SECTOR);
    free_map_release(inode->data.single_indirect, 1);
  } 
  delete_sectors(inode->data.directs, min(total, DIRECT_SIZE));
  free(mass);
  free(tempo);
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset)
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0)
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;
      lock_acquire(&cache_lock);
      cache_entry* entry = lookup_cache(&cache_map, sector_idx);
      if(entry == NULL){
        entry = cache_insert(sector_idx, false);
        block_read (fs_device, sector_idx, entry->buffer);
      }
      memcpy (buffer + bytes_read, entry->buffer + sector_ofs, chunk_size);
      lock_release(&cache_lock);
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset)
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  while (size > 0)
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;
      lock_acquire(&cache_lock);
      cache_entry* entry = lookup_cache(&cache_map, sector_idx);
      if(entry == NULL){
        entry = cache_insert(sector_idx, true);
        block_read (fs_device, sector_idx, entry->buffer);
      }
      
      memcpy (entry->buffer + sector_ofs, buffer + bytes_written, chunk_size);
      lock_release(&cache_lock);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode)
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode)
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}
