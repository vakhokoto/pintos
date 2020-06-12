#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#ifdef VM
#include "vm/frame.h"
#include "vm/page.h"
#endif


static thread_func start_process NO_RETURN;
static bool load (process_execute_info* pe_info, void (**eip) (void), void **esp);
void initialize_process_execute_info(process_execute_info* pe_info, char* line);
void initialize_child_info(child_info* ch_info);
struct child_info* get_child_struct(struct thread* cur, tid_t child_tid UNUSED);
void remove_child_struct(struct thread* cur, tid_t child_tid UNUSED);
void destroy_file_descriptors(struct thread* cur);
void destroy_children(struct thread* cur);

/* initializes child_info struct */
void initialize_child_info(child_info* ch_info) {
  ch_info->wait_status = !WAITING;
  ch_info->exit_status = -1;
  ch_info->child_tid = 0;
  sema_init(&(ch_info->sem), 0);
}

/* initializes process_execute_info struct according to the given line */
void initialize_process_execute_info(process_execute_info* pe_info, char* line) {
    char* tok_ptr = NULL;
    char* token = strtok_r(line, " ", &tok_ptr);
    // set file name
    memcpy(pe_info->file_name, token, strlen(token) + 1);
    // set arguments
    pe_info->tot_len = 0;
    pe_info->load_success = 0;
    int i = 0;
    while(i < 32) {
      if(token == NULL) {
        pe_info->argv[i] = NULL;
        pe_info->argc = i;
        break;  
      }
      pe_info->argv[i] = malloc(4*PATH_MAX);
      int len = strlen(token) + 1;
      memcpy(pe_info->argv[i], token, len);
      pe_info->tot_len += len;
      token = strtok_r(NULL, " ", &tok_ptr);
      i++;
    }
    pe_info->tot_len += (pe_info->tot_len + 4) % 4;
}

/* frees malloc variables from process_execute_info */
void destroy_process_execute_info(process_execute_info* pe_info) {
  size_t i;
  for(i = 0; i < pe_info->argc; i++)
    free(pe_info->argv[i]);
  free(pe_info);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute (const char *file_name) {
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  char* fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  child_info* ch_info = malloc(sizeof(child_info));
  process_execute_info* pe_info = malloc(sizeof(process_execute_info));

  if (ch_info == NULL || pe_info == NULL){
    palloc_free_page (fn_copy);
    if(ch_info != NULL){
      free(ch_info);
    }
    if(pe_info != NULL){
      free(pe_info);
    }
    return TID_ERROR;
  }
  
  initialize_child_info(ch_info);
  initialize_process_execute_info(pe_info, fn_copy);

  /* Push Child's struct in Parent's list */
  list_push_back(&thread_current()->children, &(ch_info->elem));
  /* Create a new thread to execute FILE_NAME. */
  ch_info->child_tid = thread_create (pe_info->file_name, PRI_DEFAULT, start_process, pe_info);
  
  /* Waiting to load */
  sema_down(&(ch_info->sem));
  if (ch_info->child_tid == TID_ERROR || !pe_info->load_success) {
    list_pop_back(&thread_current()->children);
    palloc_free_page (fn_copy);
    destroy_process_execute_info(pe_info);
    free(ch_info);
    return TID_ERROR;
  }
  destroy_process_execute_info(pe_info);
  palloc_free_page (fn_copy);
  return ch_info->child_tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process (void *pe_info_) {
  process_execute_info* pe_info = (process_execute_info*)pe_info_;
  struct intr_frame if_;
  bool success;
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load(pe_info, &if_.eip, &if_.esp);
  pe_info->load_success = success;

  /* let parent to go on its job */
  sema_up(&(get_child_struct(thread_current()->parent, thread_tid())->sem));
  
  /* If load failed, quit. */
  if (!success)
    thread_exit ();


  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* finds child threads PEInfo struct by threads TID*/
struct child_info* get_child_struct(struct thread* cur, tid_t child_tid UNUSED) {
  ASSERT(cur != NULL);
  struct list_elem* e;
  for (e = list_begin(&(cur->children)); e != list_end(&(cur->children)); e = list_next(e)) {
      struct child_info* ch_info = list_entry(e, struct child_info, elem);
      if(ch_info->child_tid == child_tid)
        return ch_info;
  }
  return NULL;
}

/* removes child threads PEInfo struct by threads TID*/
void remove_child_struct(struct thread* cur, tid_t child_tid UNUSED) {
  struct list_elem* e;
  for (e = list_begin(&(cur->children)); e != list_end(&(cur->children)); e = list_next(e)) {
      struct child_info* ch_info = list_entry(e, struct child_info, elem);
      if(ch_info->child_tid == child_tid) {
        list_remove(e);
        free(ch_info);
        return;
      }
  }
}

/* deletes all child's structures from cur->children list*/
void destroy_children(struct thread* cur) {
  while (!list_empty (&(cur->children))){
    struct list_elem *e = list_pop_front (&(cur->children));
    struct child_info* ch_info = list_entry(e, struct child_info, elem);
    free(ch_info);
  }
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.
   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait (tid_t child_tid UNUSED) {
  struct child_info* ch_info = get_child_struct(thread_current(), child_tid);

  /* check if this process already waiting child or tid is valid. */
  if(ch_info == NULL || ch_info->wait_status == WAITING || thread_tid() == child_tid) 
    return -1;

  /* set wating status */
  ch_info->wait_status = WAITING;
  
  /* waits child's exit */
  sema_down(&(ch_info->sem));
  
 // ASSERT(ch_info->wait_status != WAITING);
  int exit_status = ch_info->exit_status;
  remove_child_struct(thread_current(), child_tid);
  return exit_status;
}


/* Closes and deletes all files from cur->file list*/
void destroy_file_descriptors(struct thread* cur) {
    while (!list_empty (&(cur->file_list))){
      struct list_elem *e = list_pop_front (&(cur->file_list));
      struct file_info_t* f_info = list_entry(e, struct file_info_t, elem);
      file_close(f_info->file);
      free(f_info);
    }
}

/* Free the current process's resources. */
void process_exit (void) {
  struct thread *cur = thread_current();
  printf("%s: exit(%d)\n", cur->name, cur->exit_status);
  // if (cur->exit_status == -1){
  //   printf("petaxa\n");
  // }

  /* Destroy the current process's files */
  destroy_file_descriptors(cur);

  /* Destroy the current process's children */
  destroy_children(cur);
  
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  uint32_t *pd = cur->pagedir;
  if (pd != NULL) {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
      #ifdef VM
      supplemental_page_table_destroy(&(thread_current()->supp_table));
      #endif
  }

  /* update child's struct */
  child_info* ch_info = get_child_struct(cur->parent, thread_tid());
  
  /* noone waits cur thread */
  if(ch_info == NULL) return;


  /* update parent's referencing struct to cur*/
  ch_info->wait_status = !WAITING;
  ch_info->exit_status = cur->exit_status;
  if (thread_current() ->my_file){
    file_close (thread_current() ->my_file);
  }
  sema_up(&(ch_info->sem));
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, process_execute_info* pe_info);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (process_execute_info* pe_info, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  char* file_name = pe_info->file_name;


  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();
  
  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }
  

  thread_current()->my_file=file;
  file_deny_write(file);
  


  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }
  
  /* Set up stack. */
  if (!setup_stack (esp, pe_info))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
 // file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:
        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.
        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.
   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
//  printf("LOADING\n");
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      #ifdef VM
      uint8_t *kpage = frame_get_page(PAL_USER, upage);
      #else
      uint8_t *kpage = palloc_get_page (PAL_USER);
      #endif
      
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          // SHEVCVALET
          #ifdef VM
          frame_free_page(upage);
          #else
          palloc_free_page (kpage);
          #endif
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          // SHEVCVALET
          #ifdef VM
          frame_free_page(upage);
          #else
          palloc_free_page (kpage);
          #endif

         // printf("bbbbbb\n");
          return false;
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, process_execute_info* pe_info)
{
  uint8_t *kpage;
  bool success = false;
  #ifdef VM
  kpage = frame_get_page(PAL_USER | PAL_ZERO, ((uint8_t *) PHYS_BASE) - PGSIZE);
  #else
  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  #endif
  // SHEVCVALET UNDA IFDEF
  //printf("------SETUPPING STACK\n");
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success){
        *esp = PHYS_BASE;
        *esp -= pe_info->tot_len;
        void* pointers[pe_info->tot_len];
        int i = 0;
        int offset = 0;
        int len = 0;
        while(i < pe_info->argc){
          len = strlen(pe_info->argv[i]) + 1;
          pointers[i] = *esp + offset;
          memcpy(*esp + offset, pe_info->argv[i], len);
          offset += len;
          i++;
        }

        *esp -= 4;
        *(int*) *esp = 0;

        *esp -= sizeof(char*) * (pe_info->argc+1);
        i = 0;
        offset = 0;
        while(i < pe_info->argc){
          *((void**)(*esp + i*sizeof(char*))) = pointers[i];
          offset += sizeof(char*);
          i++;
        }     

        *((int*) (*esp + offset)) = 0;
        *esp -= sizeof(char*);
        *((void**) *esp) = (*esp + sizeof(char*));

        *esp -= sizeof(int);
        *((int*) *esp) = pe_info->argc;

        *esp -= sizeof(void*);
        *((int*) *esp) = 0;
      } else{
        #ifdef VM
        frame_free_page(((uint8_t *) PHYS_BASE) - PGSIZE);
        #else
        palloc_free_page (kpage);
        #endif
        // SHEVCVALET
      }
        
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
    // if (pagedir_get_page (t->pagedir, upage) != NULL){
    //   printf("Not NULL %d  %d\n", upage, kpage);
    // } else {
    //   printf("INSTALLING %d %d\n", upage, kpage);
    // }
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
