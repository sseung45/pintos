#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "lib/user/syscall.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call!\n");
  //thread_exit ();

  int args[4];
  int *esp = f->esp;
  check_user_address(esp);

  switch (*esp) {
    case SYS_HALT: // 0 arguement
      halt();
      break;
    case SYS_EXIT: // 1 arguement
      get_argument(esp, args, 1);
      exit(args[0]);
      break;
    case SYS_EXEC: // 1 arguement
      get_argument(esp, args, 1);
      f->eax = exec((const char *)(args[0]));
      break;
    case SYS_WAIT:
      get_argument(esp, args, 1); // 1 arguement
      f->eax = wait((pid_t *)(args[0]));
      break;
    case SYS_CREATE: // 2 arguements
      get_argument(esp, args, 2);
      f->eax = create((const char *)(args[0]), (const char *)(args[1]));
      break;
    case SYS_REMOVE: // 1 arguement
      get_argument(esp, args, 1);
      f->eax = remove((const char *)(args[0]));
      break;
    case SYS_OPEN: // 1 arguement
      get_argument(esp, args, 1);
      f->eax = open((const char *)(args[0]));
      break;
    case SYS_FILESIZE: // 1 arguement
      get_argument(esp, args, 1);
      f->eax = filesize((int)(args[0]));
      break;
    case SYS_READ: // 3 arguement
      get_argument(esp, args, 3);
      f->eax = filesize((int)(args[0]), (void *)(args[1]), (unsigned)(args[2]));
      break;
    case SYS_WRITE: // 3 arguement
      get_argument(esp, args, 3);
      f->eax = write((int)(args[0]), (const void *)(args[1]), (unsigned)(args[2]));
      break;
    case SYS_SEEK: // 2 arguement
      get_argument(esp, args, 2);
      seek((int)(args[0]), (unsigned)(args[1]));
      break;
    case SYS_TELL: // 1 arguement
      get_argument(esp, args, 1);
      f->eax = tell((int)(args[0]));
      break;
    case SYS_CLOSE: // 1 arguement
      get_argument(esp, args, 1);
      f->eax = tell((int)(args[0]));
      break;
  }
}

void halt() {
  shutdown_power_off();
}

void exit(int status){
  struct thread *t = thread_current();

  printf("%s: exit(%d)\n", t->name, status);

  thread_current()->exit_status = status;

  int fd_max = thread_current()->fd_count;
  for (int i = 2; i <= fd_max; i++) {
    if (thread_current()->fd[i] != NULL)
      close(i);
  }

  thread_exit();
}

pid_t exec(const char *cmdline) {
  return process_execute(cmdline);
}

int wait(pid_t pid) {
  return process_wait(pid);
}

bool create(const char *file, unsigned initial_size) {
  if (file == NULL)
    exit(-1);
  return filesys_create(file, initial_size);
}

bool remove(const char *file) {
  if (file == NULL)
    exit(-1);
  return filesys_remove(file);
}

int open(const char *file) {
  check_user_address(file);
  struct file *open_file = filesys_open(file);
  int fd_idx = thread_current()->fd_count;
  if (open_file == NULL || fd_idx < 128)
    return -1;

  thread_current()->fd[fd_idx] = open_file;
  thread_current()->fd_count++;
  return fd_idx;
}

int filesize(int fd)
{
  struct file *f = thread_current()->fd[fd];
  if (f == NULL)
    exit(-1);
  return file_length(f);
}

int read(int fd, void *buffer, unsigned size) {
  check_user_address(buffer);
  if (fd == 0) {  // stdin
    int idx = 0;
    for (; idx < size; idx++)
      if (((char *)buffer)[idx] == '\0')
        break;
    return idx;
  }

  // fd != stdin
  struct file *f = thread_current()->fd[fd];
  if (f == NULL)
    exit(-1);
  return file_read(f, buffer, size);
}

int write(int fd, const void *buffer, unsigned size) {
  check_user_address(buffer);
  if (fd == 1) {  // stdout
    putbuf(buffer, size);
    return size;
  }

  // fd != stdout
  struct file *f = thread_current()->fd[fd];
  if (f == NULL)
    exit(-1);
  return file_write(f, buffer, size);
}

void seek(int fd, unsigned position) {
  struct file *f = thread_current()->fd[fd];
  if (f == NULL)
    exit(-1);
  return file_seek(f, position);
}

unsigned tell(int fd) {
  struct file *f = thread_current()->fd[fd];
  if (f == NULL)
    exit(-1);
  return file_tell(f);
}

void close(int fd) {
  struct file *f = thread_current()->fd[fd];
  if (f == NULL)
    exit(-1);
  f = NULL;
  file_close (f);
}

void check_user_address(void *addr) {
  // 포인터가 user 영역 주소를 가리키는지 확인
  if (!is_user_vaddr(addr) || is_kernel_vaddr(addr) || addr == NULL)
    exit(-1);
}

void get_argument(void *esp, int *arg , int count) {
  uint32_t *sp = esp;
  int cnt = 0;
  for (;count > 0; count--) {
    check_user_address(sp + 4);
    arg[cnt] = sp + 4;
    cnt ++;
    sp += 4;
  }
}
