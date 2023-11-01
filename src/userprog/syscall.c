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
      f->eax = exec((const char *)(&args[0]));
    case SYS_WAIT:
      get_argument(esp, args, 1); // 1 arguement
      f->eax = wait((pid_t *)(&args[0]));
    case SYS_CREATE: // 2 arguements
      get_argument(esp, args, 2);
      f->eax = create((const char *)(&args[0]), (const char *)(&args[1]));
    case SYS_REMOVE: // 1 arguement
      get_argument(esp, args, 1);
      f->eax = remove((const char *)(&args[0]));
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_READ:
    case SYS_WRITE:
    case SYS_SEEK:
    case SYS_TELL:
    case SYS_CLOSE:
  }
}

void halt() {
  shutdown_power_off();
}

void exit(int status){
  struct thread *t = thread_current();

  printf("%s: exit(%d)\n", t->name, status);

  thread_exit();
}

pid_t exec(const char *cmdline) {
  return process_execute(cmdline);
}

int wait (pid_t pid) {
  return process_wait(pid);
}

bool create(const char *file, unsigned initial_size) {
  if (file == NULL)
    exit(-1);
  else
    return filesys_create(file, initial_size);
}

bool remove(const char *file) {
  if (file == NULL)
    exit(-1);
  else
    return filesys_remove(file);
}

void check_user_address(void *addr) {
  // 포인터가 user 영역 주소를 가리키는지 확인
  if (!is_user_vaddr(addr) || is_kernel_vaddr(addr) || addr == NULL) {
    exit(-1);
  }
}

void get_argument(void *esp, int *arg , int count) {
  uint32_t *sp = esp;
  int cnt = 0;
  for (;count != 0; count--) {
    check_user_address(sp + 4);
    arg[cnt] = sp + 4;
    cnt ++;
    sp = sp + 4;
  }
}
