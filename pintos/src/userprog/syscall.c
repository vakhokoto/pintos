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

void syscall_init (void) {
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
      f->eax = handle_create(file, initial_size); break;
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

bool handle_create(const char *file, unsigned initial_size) {
  // need lock?
  // return filesys_create(file, initial_size);
}

bool handle_remove(const char *file) {
  // need lock?
  // return filesys_remove(file);
}

int handle_open(const char *file) {
  // need lock?
  // struct file *file_reopen (struct file *);
}

int handle_filesize(int fd) {
  // need lock?
}

int handle_write(int fd, const void *buffer, unsigned size) {
  
}

void handle_seek(int fd, unsigned position) {

}

unsigned handle_tell(int fd) {

}

void handle_close(int fd) {

}
