#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "lib/user/syscall.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);
/* syscalls part 1 */
int handle_practice(int i);
void handle_halt(void);
void handle_exit(int status);
tid_t handle_exec(const char* cmd_line);
int handle_wait(int pid);
/* syscalls part 2 */
bool handle_create(const char *file, unsigned initial_size);
bool handle_remove(const char *file);
int handle_open(const char *file);
int handle_filesize(int fd);
int handle_write(int fd, const void *buffer, unsigned size);
int handle_read(int fd, void *buffer, unsigned size);
void handle_seek(int fd, unsigned position);
unsigned handle_tell(int fd);
void handle_close(int fd);

struct file_info_t* get_file_info(int fd, struct list file_list);
bool buffer_available(void* buffer, unsigned size);

struct lock file_lock;


void syscall_init (void) {
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}



static void syscall_handler (struct intr_frame *f UNUSED) {
  uint32_t SYSCALL_NUM = ((uint32_t*) f->esp)[0];
  printf("System call number: %d\n", SYSCALL_NUM);

  void* argv = f->esp + sizeof (uint32_t); 
  switch(SYSCALL_NUM) {
    case SYS_PRACTICE: {
      int i = *(int*)argv;
      f->eax = handle_practice(i); 
      break;
    }case SYS_HALT: {
      handle_halt(); break;
    }case SYS_EXIT: {
      int status = *(int*)argv;
      handle_exit(status); 
      break;
    }case SYS_EXEC: {
      const char* cmd_line = (const char*)argv;
      f->eax = handle_exec(cmd_line); 
      break;
    }case SYS_WAIT: {
      int pid = *(int*)argv;
      f->eax = handle_wait(pid); 
      break;
    }case SYS_CREATE: {
      const char* file = (const char*)argv;
      unsigned initial_size = *(unsigned*)(argv + sizeof file);
      f->eax = handle_create(file, initial_size);
      break;
    }case SYS_REMOVE: {
      const char* file = (const char*)argv;
      f->eax = handle_remove(file); 
      break;
    }case SYS_OPEN: {
      const char* file = (const char*)argv;
      f->eax = handle_open(file); 
      break;
    }case SYS_FILESIZE: {
      int fd = *(int*)argv;
      f->eax = handle_filesize(fd); 
      break;
    }case SYS_WRITE: {
      int fd = *(int*)argv;
      const void* buffer = (const void*)(argv + sizeof fd);
      unsigned size = *(unsigned*)(argv + sizeof fd + sizeof buffer);
      f->eax = handle_write(fd, buffer, size); 
      break;
    }case SYS_READ: {
      int fd = *(int*)argv;
      void* buffer = (void*)(argv + sizeof fd);
      unsigned size = *(unsigned*)(argv + sizeof fd + sizeof buffer);
      f->eax = handle_read(fd, buffer, size); 
      break;
    }case SYS_SEEK: {
      int fd = *(int*)argv;
      unsigned position = (unsigned)(argv + sizeof fd);
      handle_seek(fd, position); 
      break;
    }case SYS_TELL: {
      int fd = *(int*)argv;
      f->eax = handle_tell(fd); 
      break;
    }case SYS_CLOSE: {
      int fd = *(int*)argv;
      handle_close(fd); 
      break;
    }default:
      printf("Not Recognized syscall."); 
      return;
  }
}

// Handle Syscalls Here:
int handle_practice(int i) {
  return ++i;
}

void handle_halt() {
  // need to save states?
  shutdown_power_off();
}

void handle_exit(int status) {
  printf("%s: exit(%d)\n", &thread_current ()->name, status);
  thread_exit();
}

tid_t handle_exec(const char* cmd_line) {
  return process_execute(cmd_line);
}

int handle_wait(int pid) {
  return process_wait(pid);
}

bool handle_create(const char *filename, unsigned initial_size) {
  lock_acquire(&file_lock);
  bool is_created = filesys_create(filename, initial_size);
  lock_release(&file_lock);
  return is_created;
}


/*
 *  Deletes the file called filename. Returns true if successful,
 *  false otherwise. A file may be removed regardless of whether it is open or closed, and removing an
 *  open file does not close it. See Removing an Open File, for details. 
*/
bool handle_remove(const char *filename) {
  lock_acquire(&file_lock);
  bool removed = filesys_remove(filename);
  lock_release(&file_lock);

  if (!removed){
    perror("File Removed Unsuccessfully\n");
  }
  return true; 
}

/* couts the size of file from struct file * 
  by iterating through the list till the end and
  counting the sum of the struct inode_disk -> length in the way */
int count_size(struct file *file){
  /* inode list */
  struct inode *inode = file -> inode;

  /* size of file */
  int size = 0;

  while (inode != NULL){
    size += inode -> data.length;

    /* next block */
    inode = (struct inode *) inode -> elem.next;
  }

  return size;
}

/* opens file with FILENAME and returns 
  file desctiptor of that and if there is no file 
  with FILENAME than returns -1 */
int handle_open(const char *filename) {
  ASSERT (strlen(filename) <= 14);

  lock_acquire(&file_lock);

  /* file descriptor */
  int new_file_fd = -1;

  /* creating file */
  struct file *new_file = filesys_open(filename);

  /* return -1 if file can't be created */
  if (new_file == NULL){
    lock_release(&file_lock);
    return new_file_fd;
  }

  /* getting current thread/process */
  struct thread *cur_thread = thread_current();

  /* finding next file descriptor */
  struct list_elem *cur_last_elem = list_back(&cur_thread -> file_list);

  file_info_t *opened_file = malloc(sizeof(file_info_t));

  if (cur_last_elem == NULL){
    new_file_fd = 3;
  } else {
    file_info_t *f_info = list_entry(cur_last_elem, file_info_t, elem);
    new_file_fd = f_info -> fd + 1;
  }

  /* storing file data in thread files list */
  opened_file -> fd = new_file_fd;
  opened_file -> file = new_file;
  opened_file -> size = count_size(new_file);
  new_file -> pos = 0;

  list_push_back(&cur_thread -> file_list, &opened_file -> elem);

  lock_release(&file_lock);

  return new_file_fd;
}

int handle_filesize(int fd) {
  struct thread* cur_thread = thread_current();
  file_info_t* file_info = get_file_info(fd, cur_thread -> file_list);
  ASSERT(file_info != NULL);
  int filesize = 1;
  // TODO

  return filesize;
}


int handle_write(int fd, const void *buffer, unsigned size) {
  ASSERT(buffer != NULL && size >= 0);
  ASSERT(buffer_available(buffer, size));
  //ASSERT(put_user(buffer + size));


}


/**
 * Reads size bytes from the file open as fd into buffer. Returns the number
 * of bytes actually read (0 at end of file), or -1 if the file could not be read 
 * (due to a condition other than end of file). Fd 0 reads from the keyboard using
 * input_getc().
 */
int handle_read(int fd, void* buffer, unsigned size) {
  ASSERT(buffer != NULL && size >= 0); 
  

  lock_acquire(&file_lock);

  ASSERT(buffer_available(buffer, size));
  //ASSERT(get_user(buffer + size));

  if (fd == 0){
    char* stdio_buffer = (char*)buffer;
    int i = 0;
    while(i < size){
      uint8_t key = input_getc();
      *(stdio_buffer + i) = key; 
      i++;
    }
  } else {
    struct thread* cur_thread = thread_current();
    file_info_t* file_info = get_file_info(fd, cur_thread -> file_list);
    ASSERT(file_info == NULL &&file_info -> file == NULL);
    file_read(file_info -> file, buffer, size);
  }
  lock_release(&file_lock);
  // Read from file
  
}

/*
 *  Changes the next byte to be read or written 
 *  in open file fd to position, expressed in bytes from the beginning of the file.
 */
void handle_seek(int fd, unsigned position) {
  struct thread* cur_thread = thread_current();

  lock_acquire(&file_lock);
  
  file_info_t* file_info = get_file_info(fd, cur_thread -> file_list);
  ASSERT(file_info == NULL &&file_info -> file == NULL);

  file_seek (file_info -> file, position);

  lock_release(&file_lock);
}


/*
 * Returns the position of the next byte to be read or written in
 *  open file fd, expressed in bytes from the beginning of the file.
*/
unsigned handle_tell(int fd) {
  struct thread* cur_thread = thread_current();

  lock_acquire(&file_lock);
  file_info_t* file_info = get_file_info(fd, cur_thread -> file_list);

  unsigned pos = file_tell (file_info -> file);

  lock_release(&file_lock);

  return pos;
}

void handle_close(int fd) {

}

/**
 * Finds file info structure by its file descriptor 
 * Returns file_info_t structure pointer.
 */ 
struct file_info_t* get_file_info(int fd, struct list file_list){
  struct list_elem* e;
  for (e = list_begin(&file_list); e != list_end(&file_list); e = list_next(e)) {
      file_info_t* file_info = list_entry(e, file_info_t, elem);
      if(file_info -> fd == fd)
        return file_info;
  }
  return NULL;
}

/**
 * Returns true if size amount of bytes is available in the buffer
 * Returns false otherwise.
 */
bool buffer_available(void* buffer, unsigned size){
  if(is_kernel_vaddr((void*)buffer + size)){
    return false;
  }


  return true;
}


/* Reads a byte at user virtual address UADDR.
 * UADDR must be below PHYS_BASE.
 * Returns the byte value if successful, -1 if a segfault
 * occurred. */
static int get_user (const uint8_t *uaddr){
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
  : "=&a" (result) : "m" (*uaddr));
  return result;
}



/* Writes BYTE to user address UDST.
 * UDST must be below PHYS_BASE.
 * Returns true if successful, false
 * if a segfault occurred. 
 */
static bool put_user (uint8_t *udst, uint8_t byte){
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
  : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}