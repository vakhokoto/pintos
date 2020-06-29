#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "threads/thread.h"

/* Partition thnameat contains the file system. */
struct block *fs_device;
struct dir* get_starting_dir(char* path);
static void do_format (void);
static int get_next_part (char part[NAME_MAX + 1], const char **srcp);
bool split_dir_path(char* dir, struct dir **res_dir, char* name);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format)
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format)
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void)
{
  dispose_cache();
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size)
{ 

  char new_name[256]; new_name[0] = '\0';
  struct dir* mkdir = NULL;
  // printf("making filesys - %s\n", name);
  bool success;
  success = split_dir_path(name, &mkdir, new_name);
  if(!mkdir) mkdir = dir_open_root();
  // printf("%s [%s]", name, new_name);
  block_sector_t inode_sector = 0;
  success =  success && (mkdir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, 0)
                  && dir_add (mkdir, new_name, inode_sector));
  if (!success && inode_sector != 0){
    free_map_release (inode_sector, 1);
    // printf("NOT SUCC\n");
  }
  dir_close (mkdir);


  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  
  
  char new_name[256]; new_name[0] = '\0';
  struct dir* dir = NULL;
  // printf("OPENING - %s\n", name);
  bool success;
  success = split_dir_path(name, &dir, new_name);
    // printf("OP - [%s]\n", new_name);
  if(!dir) dir = dir_open_root();

  if (strcmp(name, "/")  == 0){
    thread_current()->dir = dir_open_root();
    return file_open((dir_get_inode(dir_open_root())));
  } else if ( strcmp(name, ".") == 0){
    return file_open((dir_get_inode(thread_current()->dir)));
  }

  // struct dir *dir = get_starting_dir (name);
  struct inode *inode = NULL;

  if (dir != NULL)
    dir_lookup (dir, new_name, &inode);
  // printf("OPENING %s %d %d\n", name, inode != NULL, dir != NULL);
  dir_close (dir);

  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name)
{
  char new_name[256]; new_name[0] = '\0';
  struct dir* dir = NULL;
  // printf("making filesys - %s\n", name);
  bool success;
  success = split_dir_path(name, &dir, new_name);
  // struct dir *dir = get_starting_dir (name);
  success = success && dir != NULL && dir_remove (dir, new_name);
  dir_close (dir);

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}

/* Gets starting directory for searching files*/
struct dir* get_starting_dir(char* path){
  struct dir* dir = NULL;
  if(path[0] == '/' || !thread_current()->dir) {
    // printf("OPENING ROOT\n");
    dir = dir_open_root();
  } else {
    // printf("CHDDD\n");
    dir = dir_reopen(thread_current()->dir);
  }
  // ASSERT(dir != NULL);
  return dir;
}

struct dir* configure_dir(char* path) {
  struct dir* mkdir = get_starting_dir(path);
  char next[15];
  int found;
  bool end_string = false;
    struct inode* inode;
  while(true){
    found = get_next_part(next, &path);
    // printf("NEXT filename - %s, found %d\n", next, found);
    if (found == -1){
      return NULL;
    } else if (found == 1){
        // Something's wrong, name's been found in last iteration
        if (dir_lookup (mkdir, next, &inode)){
          dir_close(mkdir);
          mkdir = dir_open(inode);
        } else {
          // printf("NULLLLLL\n");
          return NULL;
        }
    } else {
      // end of string
      end_string = true;
      break;
    }
  }
  // printf("%d emd\n", end_string);
  if (end_string) return mkdir;
  return NULL;
} 

/*Changes the current working directory of the process
  to dir, which may be relative or absolute. Returns true 
  if successful, false on failure.*/
bool filesys_chdir(const char* dir) {
  struct dir* chdir = configure_dir(dir);
  if(!chdir) return false;
  if (thread_current()->dir != NULL){
    dir_close(thread_current()->dir);}
  thread_current()->dir = chdir;
  
  return true;
}


/* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
next call will return the next file name part. Returns 1 if successful, 0 at
end of string, -1 for a too-long file name part. */
static int get_next_part (char part[NAME_MAX + 1], const char **srcp) {
  const char *src = *srcp;
  char *dst = part;
  /* Skip leading slashes. If it’s all slashes, we’re done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;
  /* Copy up to NAME_MAX character from SRC to DST.  Add null terminator. */
  while (*src != '/' && *src != '\0') {
    if (dst < part + NAME_MAX)
      *dst++ = *src;
    else
      return -1;
    src++;
  }
  *dst = '\0';
  /* Advance source pointer. */
  *srcp = src;
  return 1;
}

//ES SPLIT AR MUSHAOBS VCVLI -- DACHI
bool split_dir_path(char* dir, struct dir **res_dir, char* name) {
  struct dir* mkdir = get_starting_dir(dir);
  char next[15];
  int found;
  // printf("DEVIWYE\n");
  found = get_next_part(name, &dir);
  // printf("filename - %s found %d\n", name, found);
  if (!(found > 0)) {
    return (found > 0);
  }
  
    struct inode* inode;
  while(true){
    found = get_next_part(next, &dir);
    // printf("NEXT filename - %s, found %d\n", next, found);
    if (found == -1){
      return false;
    } else if (found == 1){
        // Something's wrong, name's been found in last iteration
        if (dir_lookup (mkdir, name, &inode)){
          dir_close(mkdir);
          mkdir = dir_open(inode);
          strlcpy (name, next, 15);
        } else {
          return false;
        }
    } else {
      // end of string
      break;
    }
  }
  *res_dir = mkdir;
  // printf("MOVRCHI, \n");
  return true;
}


/*Creates the directory named dir, which may be relative or absolute. Returns true if successful, 
  false on failure. Fails if dir already exists or if any
  directory name in dir, besides the last, does not already exist. 
  That is, mkdir(“/a/b/c”) succeeds only if /a/b already exists and /a/b/c does not.*/
bool filesys_mkdir(const char* dir) {
  char name[256];
  struct dir* mkdir = NULL;
  // printf("making dir - %s\n", dir);
  bool success;
  success = split_dir_path(dir, &mkdir, name);
  if (!success || !mkdir) return false;
  // printf("splitted %s\n", name);

  block_sector_t inode_sector = 0;
  success = (mkdir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, 0, 1)
                  && dir_create (inode_sector, inode_get_inumber (dir_get_inode (mkdir))) 
                  && dir_add (mkdir, name, inode_sector));
  if (!success && inode_sector != 0){
    free_map_release (inode_sector, 1);
    // printf("not success\n");
  }
  dir_close (mkdir);

  return success;
}

