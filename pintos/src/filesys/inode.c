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
#include "cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define BUF_SIZE 64
#define MAX_FILE_SIZE 16636
#define DIRECT_SIZE 123
#define SINGLE_SIZE 128
#define ON_SINGLE_SECTOR 128
#define DOUBLE_SIZE 128 * 128


/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t directs[DIRECT_SIZE];
    block_sector_t single_indirect;
    block_sector_t double_indirect;
    
    int dir;
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
  };

bool inode_create_single(struct inode_disk *, size_t, size_t);
bool inode_create_double(struct inode_disk *, size_t, size_t);
bool inode_create_direct(struct inode_disk *, size_t, size_t);

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
byte_to_sector (struct inode *inode, off_t offset) {
  ASSERT(offset >= 0);
  ASSERT(inode != NULL);
  size_t cnt_sectors = (inode->data.length + BLOCK_SECTOR_SIZE - 1) / BLOCK_SECTOR_SIZE;

  if (offset < cnt_sectors * BLOCK_SECTOR_SIZE) {
    off_t idx = offset / BLOCK_SECTOR_SIZE;

    if(idx < DIRECT_SIZE)
      return inode->data.directs[idx];
    
    if(idx < DIRECT_SIZE + SINGLE_SIZE) {
      block_sector_t block[ON_SINGLE_SECTOR];
      cache_read(fs_device, inode->data.single_indirect, block);
      return block[idx - DIRECT_SIZE];
    }

  }
  return -1;
}

void try_allocate_sectors(struct inode *inode, off_t idx) {
  size_t owned_sectors = (inode->data.length + BLOCK_SECTOR_SIZE - 1) / BLOCK_SECTOR_SIZE; // 1dan gadanomrili
  size_t last_sector = (idx + BLOCK_SECTOR_SIZE) / BLOCK_SECTOR_SIZE; // 1dan gadanomrili

  if(owned_sectors >= last_sector) 
    return;
  // printf("------------ GROWING ----------- \n");
  
  if(owned_sectors < DIRECT_SIZE) {
    size_t start_sector = owned_sectors;
    size_t num_alloc = min(last_sector - start_sector, DIRECT_SIZE - start_sector);

    inode_create_direct(&inode->data, start_sector, num_alloc);

    owned_sectors += num_alloc;
  }

  if(owned_sectors < last_sector && owned_sectors < DIRECT_SIZE + SINGLE_SIZE) {
    size_t start_sector = owned_sectors;
    size_t num_alloc = min(last_sector - start_sector, DIRECT_SIZE + SINGLE_SIZE - start_sector);

    inode_create_single(&inode->data, start_sector - DIRECT_SIZE, num_alloc);

    owned_sectors += num_alloc;
  }
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void)
{
  list_init (&open_inodes);
  cache_init();
  // lock_init(&cache_lock);
}

/* creates direct blocks for new files and fills it with 0s */
bool inode_create_direct(struct inode_disk *dsk, size_t start, size_t num_alloc){
  /* fill in with 0s for on default */
  if (num_alloc == 0){
    return true;
  }
  // printf("-------------direct-------------\n");
  if (!start){
    memset(dsk -> directs, 0, DIRECT_SIZE * sizeof(block_sector_t));
  }
  bool res = true;
  char zeros[BLOCK_SECTOR_SIZE];
  memset(zeros, 0, BLOCK_SECTOR_SIZE);

  int i;
  for (i = start; i < start + num_alloc; ++i){
    res &= free_map_allocate(1, &dsk -> directs[i]);
    if (!res)
      return res;

    /* fill in block with zeros */
    cache_write(fs_device, dsk -> directs[i], zeros);
  }

  // printf("-------------direct--ended-------------\n");
  return res;
}

/* in case file needs more than DIRECT_SIZE sectors 
  single indirect part should be added */
bool inode_create_single(struct inode_disk *dsk, size_t start, size_t num_alloc){
  // printf("------------------single------------------\n");
  if (num_alloc == 0){
    return true;
  }
  bool res = true;
  char zeros[BLOCK_SECTOR_SIZE];
  memset(zeros, 0, BLOCK_SECTOR_SIZE);

  if (start == 0){
    res &= free_map_allocate(1, &dsk->single_indirect);
  }
  block_sector_t buf[ON_SINGLE_SECTOR];
  if (start != 0){
    cache_read(fs_device, dsk -> single_indirect, buf);
  } else {
    memset(buf, 0, ON_SINGLE_SECTOR * sizeof(block_sector_t));
  }

  size_t i;
  for (i = start; i < start + num_alloc; i++){
    res &= free_map_allocate(1, &buf[i]);
    if (!res)
      return res;

    /* fill in block with zeros */
    cache_write(fs_device, buf[i], zeros);
  }
  cache_write(fs_device, dsk -> single_indirect, buf);

  // printf("------------------single--ended------------------\n");
  return res;
}

/* and in case new file siz is more thant DIRECT_SIZE + SINGLE_SIZE 
  than we need double indirect sectors */
bool inode_create_double(struct inode_disk *dsk, size_t start, size_t num_alloc){
  // // printf("-------------double-------------\n");
  if (num_alloc == 0){
    return true;
  }

  bool res = true;
  char zeros[BLOCK_SECTOR_SIZE];
  memset(zeros, 0, BLOCK_SECTOR_SIZE);

  size_t counter = num_alloc;
  size_t top_level = (start + num_alloc) / ON_SINGLE_SECTOR;

  block_sector_t d_buf[ON_SINGLE_SECTOR];
  if (start == 0){
    memset(d_buf, 0, ON_SINGLE_SECTOR * sizeof(block_sector_t));
    res &= free_map_allocate(1, &dsk->double_indirect);
  } else {
    cache_read(fs_device, dsk -> double_indirect, d_buf);
  }
  size_t low_level = start / ON_SINGLE_SECTOR;
  size_t cur = start;

  size_t i;
  for  (i = low_level; i < top_level || counter > 0; i++){
    block_sector_t buf[ON_SINGLE_SECTOR];
    memset(buf, 0, ON_SINGLE_SECTOR * sizeof(block_sector_t));

    if (cur % ON_SINGLE_SECTOR == 0){
      res &= free_map_allocate(1, &d_buf[i]);
    } else {
      cache_read(fs_device, d_buf[i], buf);
    }

    size_t j;
    for (j = cur % ON_SINGLE_SECTOR; j<min(ON_SINGLE_SECTOR, counter); j++){
      res &= free_map_allocate(1, &buf[j]);      
      if (!res)
        return res;

      /* fill in with zeros */
      cache_write(fs_device, buf[j], zeros);
    }
    
    cache_write(fs_device, d_buf[i], buf);
    size_t change = min(counter, ON_SINGLE_SECTOR);
    counter -= change;
    cur += change;
  }

  cache_write(fs_device, dsk -> double_indirect, d_buf);

  // printf("-------------double---ended-------------\n");
  return res;
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, int dir)
{
  // // printf("--------------creating--------------\n");
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
          success &= inode_create_direct(disk_inode, 0, min(sectors, DIRECT_SIZE));
          sectors -= min(sectors, DIRECT_SIZE);
        } else {
          success = true;
        }

        if (sectors > 0){
          success &= inode_create_single(disk_inode, 0, min(sectors, SINGLE_SIZE));
          sectors -= min(SINGLE_SIZE, sectors);
        }

        if (sectors > 0){
          success &= inode_create_double(disk_inode, 0, min(sectors, DOUBLE_SIZE));
        }
        disk_inode->dir = dir;
        cache_write (fs_device, sector, disk_inode);
        free (disk_inode);
      }    
    }

  // // printf("--------------creating---ended--------------\n");
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
  cache_read (fs_device, inode->sector, &inode->data);
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
    off_t new_pos = i - 251 - 1;
    off_t double_pos = new_pos / ON_SINGLE_SECTOR;
    off_t ind_pos = new_pos % ON_SINGLE_SECTOR;
    cache_read(fs_device, inode->data.double_indirect, mass);
    
    for(; i < double_pos - 1; i++){
      cache_read(fs_device, mass[i], tempo);
      delete_sectors(tempo, ON_SINGLE_SECTOR);
    }
    cache_read(fs_device, mass[double_pos], tempo);
    
    delete_sectors(tempo, ind_pos);
    delete_sectors(mass, ON_SINGLE_SECTOR);
    free_map_release(inode->data.double_indirect, 1);
  }
  if(total > DIRECT_SIZE){
    cache_read(fs_device, inode->data.single_indirect, mass);
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
  uint8_t *bounce = malloc(BLOCK_SECTOR_SIZE);

  ASSERT (bounce != NULL);

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
      
      cache_read(fs_device, sector_idx, bounce);
      memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free(bounce);

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
  uint8_t *bounce = malloc(BLOCK_SECTOR_SIZE);
  ASSERT(bounce != NULL);

  if (inode->deny_write_cnt)
    return 0;

  try_allocate_sectors(inode, offset + size - 1);
  inode->data.length = max(inode->data.length, offset + size);
  cache_write(fs_device, inode->sector, &inode->data);

  while (size > 0)
    {
      /* Sector to write, starting byte offset within sector. */
      int sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;
      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      cache_read(fs_device, sector_idx, bounce);
      
      memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
      
      cache_write(fs_device, sector_idx, bounce);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free(bounce);

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

bool is_directory(struct inode* inode) {
  return inode->data.dir;
}