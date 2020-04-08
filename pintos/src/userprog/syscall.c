#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "lib/user/syscall.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

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
void handle_seek(int fd, unsigned position);
unsigned handle_tell(int fd);
void handle_close(int fd);

struct file_info_t* get_file_info(int fd, struct list file_list);


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

  return filesys_create(filename, initial_size);
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

int handle_open(const char *filename) {
  // need lock?
  struct file *cur_file = filesys_open(filename);
  // struct thread *cur_thread = 
}

int handle_filesize(int fd) {
  struct thread* cur_thread = thread_current();
  file_info_t* file_info = get_file_info(fd, cur_thread -> file_list);
  if (file_info == NULL){
    perror("Can't find file with given descriptor\n");
  }
  int filesize = 1;
  // TODO

  return filesize;
}


int handle_write(int fd, const void *buffer, unsigned size) {
  
}

/*
 *  Changes the next byte to be read or written 
 *  in open file fd to position, expressed in bytes from the beginning of the file.
 */
void handle_seek(int fd, unsigned position) {
  struct thread* cur_thread = thread_current();

  lock_acquire(&file_lock);
  
  file_info_t* file_info = get_file_info(fd, cur_thread -> file_list);
  if (file_info == NULL || file_info -> file == NULL){
    perror("Can't find file with given descriptor\n");
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
  file_info_t* file_info = get_file_info(fd, cur_thread -> file_list);

  unsigned pos = file_tell (file_info -> file);

  lock_release(&file_lock);

  return pos;
}

void handle_close(int fd) {

}

/* Finds file info structure by its file descriptor  */ 
struct file_info_t* get_file_info(int fd, struct list file_list){
  struct list_elem* e;
  for (e = list_begin(&file_list); e != list_end(&file_list); e = list_next(e)) {
      file_info_t* file_info = list_entry(e, file_info_t, elem);
      if(file_info -> fd == fd)
        return file_info;
  }
  return NULL;
}