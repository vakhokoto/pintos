#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#define PATH_MAX 14
#define WAITING 1
#define EXITCODE_SUCCESS 0
#define EXITCODE_FAILURE 1

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

typedef struct child_info {
  struct list_elem elem;
  tid_t child_tid;
  int wait_status;
  int exit_status;
  struct semaphore sem;
} child_info;

typedef struct process_execute_info {
  // info
  int argc;
  int tot_len;
  int load_success;
  char* argv[32];
  char file_name[PATH_MAX];
} process_execute_info;

#endif /* userprog/process.h */
