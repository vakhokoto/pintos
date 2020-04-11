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
#include "lib/kernel/stdio.h"

#define PIECE_SIZE 100

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

struct file_info_t* get_file_info(int fd, struct list *file_list);
bool buffer_available(void* buffer, unsigned size);
static bool put_user (uint8_t *udst, uint8_t byte);
static int get_user (const uint8_t *uaddr);
void read_argv(void *src, void *dst, size_t bytes);

static struct lock file_lock;

void syscall_init (void) {
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler (struct intr_frame *f UNUSED) {
  if(!buffer_available(f->esp, sizeof(int))){
    handle_exit(-1);
    return;
  } 
  // printf("aq shemovidaaaaaaaaaaaaaaaaaaaaaaaaaaaaa----------------------\n");
  uint32_t SYSCALL_NUM = ((uint32_t*) f->esp)[0];
  void* argv = f->esp + sizeof (uint32_t); 
  const char* cmd_line, file;
  int fd, status, i, pid;
  const void* buffer;
  unsigned size;
  switch(SYSCALL_NUM) {
    case SYS_PRACTICE: {
      // printf("----------------practice-----------------\n");
      read_argv(argv, &i, sizeof(i));
      f->eax = handle_practice(i); 
      break;
    }case SYS_HALT: {
      // printf("----------------halt-----------------\n");
      handle_halt(); break;
    }case SYS_EXIT: {
      // printf("----------------exit-----------------\n");
      int status;
      read_argv(argv, &status, sizeof(status));
      handle_exit(status); 
      break;
    }case SYS_EXEC: {
      // printf("----------------exec-----------------\n");
      read_argv(argv, &cmd_line, sizeof(cmd_line));
      f->eax = handle_exec(cmd_line); 
      break;
    }case SYS_WAIT: {
      // printf("----------------wait-----------------\n");
      read_argv(argv, &pid, sizeof(pid));
      f->eax = handle_wait(pid); 
      break;
    }case SYS_CREATE: {
      // printf("----------------create-----------------\n");
      f->eax = handle_create(*(void**)argv, *(int*)(argv + sizeof(char*)));
      break;
    }case SYS_REMOVE: {
      // printf("----------------remove-----------------\n");
      read_argv(argv, &file, sizeof(file));
      f->eax = handle_remove(file); 
      break;
    }case SYS_OPEN: {
      // printf("----------------open-----------------\n");
      // read_argv(argv, &file, sizeof(file));
      f->eax = handle_open(*(char**)argv); 
      break;
    }case SYS_FILESIZE: {
      // printf("----------------filesize-----------------\n");
      read_argv(argv, &fd, sizeof(fd));
      f->eax = handle_filesize(fd); 
      break;
    }case SYS_WRITE: {
      // printf("----------------write-----------------\n");
      read_argv(argv, &fd, sizeof(fd));
      read_argv(argv + sizeof(fd), &buffer, sizeof(buffer));
      read_argv(argv + sizeof(fd) + sizeof(buffer), &size, sizeof(size));
      f->eax = handle_write(fd, buffer, size);
      break;
    }case SYS_READ: {
      // printf("----------------read-----------------\n");
      read_argv(argv, &fd, sizeof(fd));
      read_argv(argv + sizeof(fd), &buffer, sizeof(buffer));
      read_argv(argv + sizeof(fd) + sizeof(buffer), &size, sizeof(size));
      f->eax = handle_read(fd, buffer, size); 
      break;
    }case SYS_SEEK: {
      // printf("----------------seek-----------------\n");
      read_argv(argv, &fd, sizeof(fd));
      read_argv(argv + sizeof(fd), &size, sizeof(size));
      handle_seek(fd, size); 
      break;
    }case SYS_TELL: {
      // printf("----------------tell-----------------\n");
      read_argv(argv, &fd, sizeof(fd));
      f->eax = handle_tell(fd); 
      break;
    }case SYS_CLOSE: {
      // printf("----------------close-----------------\n");
      read_argv(argv, &fd, sizeof(fd));
      handle_close(fd); 
      break;
    }default:
      // printf("Not Recognized syscall."); 
      return;
  }
}

// Handle Syscalls Here:
/* Practice syscall - increments i by 1. */
int handle_practice(int i) {
  return ++i;
}

/* Halt syscall - terminates pintos by calling shutdown_power_off(). */
void handle_halt() {
  shutdown_power_off();
}

/* Exit syscall - terminates the current user program, returning status to the kernel. */
void handle_exit(int status) {
  // printf("%s: exit(%d)\n", &thread_current ()->name, status);
  thread_current()->exit_status = status;
  thread_exit();
}

/* Exec syscall - runs the executable whose name is given in cmd_line */
tid_t handle_exec(const char* cmd_line) {
  return process_execute(cmd_line);
}

/* Wait syscall - Waits for a child process pid and retrieves the child’s exit status */
int handle_wait(int pid) {
  return process_wait(pid);
}

/* Create syscall - creates a new ﬁle called ﬁle initially
 * initial size bytes in size. Returns true if successful, false otherwise. */
bool handle_create(const char *filename, unsigned initial_size) {
  lock_acquire(&file_lock);
  if(!buffer_available(filename, 0)){
    lock_release(&file_lock);
    handle_exit(-1);
    return false;
  }
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
    handle_exit(-1);
  }
  return true; 
}

/* opens file with FILENAME and returns 
  file desctiptor of that and if there is no file 
  with FILENAME than returns -1 */
int handle_open(const char *filename) {
  if(!buffer_available(filename, 0) || !(strlen(filename) >= 0 && strlen(filename) <= 14)){
    handle_exit(-1);
    return false;
  }

  // printf("aq shemovidaaaaaaaaaaaaaaaaaaaaaaaaaaaaa----------------------\n");

  lock_acquire(&file_lock);

  /* file descriptor */
  int new_file_fd = -1;

  /* creating file */
  struct file *new_file = filesys_open(filename);

  /* return -1 if file can't be created */
  if (new_file == NULL){
    // printf("aq shemovida %d\n", new_file_fd);
    lock_release(&file_lock);
    return new_file_fd;
  }

  /* getting current thread/process */
  struct thread *cur_thread = thread_current();

  /* finding next file descriptor */
  struct list_elem *cur_last_elem = NULL;
  if (!list_empty(&cur_thread -> file_list))
    cur_last_elem = list_back(&cur_thread -> file_list);

  file_info_t *opened_file = malloc(sizeof(file_info_t));

  if (opened_file == NULL){
    lock_release(&file_lock);
    handle_exit(-1);
    return -1;
  }

  if (cur_last_elem == NULL){
    new_file_fd = 3;
  } else {
    file_info_t *f_info = list_entry(cur_last_elem, file_info_t, elem);
    new_file_fd = f_info -> fd + 1;
  }

  /* storing file data in thread files list */
  opened_file -> fd = new_file_fd;
  opened_file -> file = new_file;
  opened_file -> size = file_length(new_file);
  // printf("aq shemoida da zoma aris -> %d\n", opened_file -> size);

  list_push_back(&cur_thread -> file_list, &opened_file -> elem);

  lock_release(&file_lock);

  return new_file_fd;
}

int handle_filesize(int fd) {
  struct thread* cur_thread = thread_current();
  file_info_t* file_info = get_file_info(fd, &cur_thread -> file_list);
  if (file_info == NULL){
    handle_exit(-1);
  }
  int filesize = file_info -> size;

  return filesize;
}


/* Writes SIZE number bytes from  buffer to file with FD descriptor 
  number. If FD == 1 than it's the special case and writing 
  should happen to the console with breaking buffer into smaller parts */
int handle_write(int fd, const void *buffer, unsigned size) {
  if(!buffer_available(buffer, 0) || fd == 0){
    handle_exit(-1);
    return false;
  }

  lock_acquire(&file_lock);

  int written_bytes = 0;

  if (fd == 1){
    putbuf(buffer, size);

    written_bytes = size;
  } else {
    /* current thread */
    struct thread *cur_thread = thread_current();
    /* file_info where the data should be written */
    file_info_t *output_file = get_file_info(fd, &cur_thread -> file_list);
    if (output_file == NULL){
      lock_release(&file_lock);
      handle_exit(-1);
      return false;
    }

    /* writing into file */
    written_bytes = file_write(output_file -> file, buffer, size);
  }

  lock_release(&file_lock);

  return written_bytes;
}


/**
 * Reads size bytes from the file open as fd into buffer. Returns the number
 * of bytes actually read (0 at end of file), or -1 if the file could not be read 
 * (due to a condition other than end of file). Fd 0 reads from the keyboard using
 * input_getc().
 */
int handle_read(int fd, void* buffer, unsigned size) {
  if(buffer == NULL || size < 0 || !buffer_available(buffer, size)){
    handle_exit(-1);
    return -1;
  } 
  int bytes_read = -1;
  lock_acquire(&file_lock);
  if (fd == 0){
    char* stdio_buffer = (char*)buffer;
    int i = 0;
    while(i < size){
      uint8_t key = input_getc();
      if (!put_user((char*)stdio_buffer + i, key)){
        lock_release(&file_lock);
        return -1;
      }
      i++;
    }
  } else {
    struct thread* cur_thread = thread_current();
    file_info_t* file_info = get_file_info(fd, &cur_thread -> file_list);
    if (file_info == NULL || file_info -> file == NULL){
      lock_release(&file_lock);
      return -1;
    }
    bytes_read = file_read(file_info -> file, buffer, size);
  }
  lock_release(&file_lock);
  return bytes_read;
}

/*
 *  Changes the next byte to be read or written 
 *  in open file fd to position, expressed in bytes from the beginning of the file.
 */
void handle_seek(int fd, unsigned position) {
  struct thread* cur_thread = thread_current();

  lock_acquire(&file_lock);
  
  file_info_t* file_info = get_file_info(fd, &cur_thread -> file_list);
  if (!(file_info == NULL &&file_info -> file == NULL)){
    lock_release(&file_lock);
    handle_exit(-1);
    return;
  }

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
  file_info_t* file_info = get_file_info(fd, &cur_thread -> file_list);

  if (file_info == NULL){
    lock_release(&file_lock);
    handle_exit(-1);
    return -1;
  }

  unsigned pos = file_tell (file_info -> file);

  lock_release(&file_lock);

  return pos;
}


void handle_close(int fd) {
  if (!(fd != 0 && fd != 1)){
    handle_exit(-1);
    return;
  }
  lock_acquire(&file_lock);

  /* current thread */
  struct thread *thread = thread_current();

  /* file info that should be closed */
  file_info_t *file = get_file_info(fd, &thread -> file_list);
  if (file != NULL){
    /* close file */
    file_close(file -> file);

    list_remove(&file -> elem);

    /* free memory allocated for file information */
    free(file);
  }
  lock_release(&file_lock);
}

/**
 * Finds file info structure by its file descriptor 
 * Returns file_info_t structure pointer.
 */ 
struct file_info_t* get_file_info(int fd, struct list *file_list){
  /* if  empty close automatically */
  if (list_empty(file_list)){
    return NULL;
  }
  struct list_elem* e;
  for (e = list_begin(file_list); e != list_end(file_list); e = list_next(e)) {
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
  if(buffer == NULL || is_kernel_vaddr((char*)buffer + size)){
    return false;
  }
  bool result = true;
  
  /* current thread */
  struct thread *cur_thread = thread_current();
  char* address = NULL;

  for (address = buffer; address < (char*) buffer + size; address += PGSIZE){
    if (pagedir_get_page(cur_thread->pagedir, address) == NULL){
      result = false;
    }
  }

  if (pagedir_get_page(cur_thread->pagedir, (char*)buffer + size - 1) == NULL){
    result = false;
  }
  return result;
}

void read_argv(void *src, void *dst, size_t bytes) {
  int i = 0;
  while(i < bytes){
    *(char*)(dst + i) = get_user(src + i++) & 255;
  }
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