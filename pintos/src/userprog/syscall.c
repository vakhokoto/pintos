#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);
void handle_pracitce(int i);
void handle_halt(void);
void handle_exit(int status);
pid_t handle_exec(const char* cmd_line);
int handle_wait(pid_t pid);

void syscall_init (void) {
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler (struct intr_frame *f UNUSED) {
  uint32_t* args = ((uint32_t*) f->esp);
  printf("System call number: %d\n", args[0]);
  switch(args[0]) {
    case SYS_PRACTICE:
      handle_practice(args[1]); break;
    case SYS_HALT:
      handle_halt(); break;
    case SYS_EXIT:
      handle_exit(args[1]); break;
    case SYS_EXEC:
      handle_exec(args[1]); break;
    case SYS_WAIT:
      handle_wait(args[1]); break;
    default:
      printf("Not Recognized syscall."); 
      return;
  }
}

// Handle Syscalls Here:
int handle_pracitce(int i) {
  return ++i;
}

void handle_halt() {
  // need to save states?
  shutdown_power_off();
}

void handle_exit(int status) {
  f->eax = status;
  printf("%s: exit(%d)\n", &thread_current ()->name, status);
  thread_exit();
}

void handle_exec(const char* cmd_line) {

}

void handle_wait(pid_t pid) {

}