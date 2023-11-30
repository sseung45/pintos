#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"

static void syscall_handler (struct intr_frame *);

struct lock file_lock;

struct file_info {
  struct file *file;
  int fd;
  struct list_elem elem;
};

struct file_info* search(struct list* file_list, int fd) {
  for (struct list_elem *e = list_begin (file_list); e != list_end (file_list); e = list_next (e)) {
    struct file_info *f = list_entry(e, struct file_info, elem);
    if (f->fd == fd)
      return f;
  }
  return NULL;
}

void close_files(struct list *file_list) {
  struct list_elem *e;
	while(!list_empty(file_list)) {
		e = list_pop_front(file_list);
		struct file_info *f = list_entry(e, struct file_info, elem);
	  file_close(f->file);
	  list_remove(e);
	  free(f);
	}
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //thread_exit ();

  int args[2];
  uint32_t *esp = f->esp;
  //check_user_address(esp);

  switch (*esp) {
    case SYS_HALT: // 0 arguement
      halt();
      break;
    case SYS_EXIT: // 1 arguement
      get_argument(esp, args, 1);
      exit((int)(args[0]));
      break;
    case SYS_EXEC: // 1 arguement
      get_argument(esp, args, 1);
      f->eax = exec((const char *)(args[0]));
      break;
    case SYS_WAIT:
      get_argument(esp, args, 1); // 1 arguement
      f->eax = wait((pid_t)(args[0]));
      break;
    case SYS_CREATE: // 2 arguements
      get_argument(esp, args, 2);
      f->eax = create((const char *)(args[0]), (unsigned)(args[1]));
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
      f->eax = read((int)(args[0]), (void *)(args[1]), (unsigned)(args[2]));
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
      close((int)(args[0]));
      break;
    case SYS_MMAP: // 2 arguement
      get_argument(esp, args, 2);
      f->eax = mmap((int)(args[0]),(void *)(args[1]));
      break;
    case SYS_MUNMAP: // 1 arguement
      get_argument(esp, args, 1);
      munmap((mapid_t)(args[0]));
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
  lock_acquire(&file_lock);
  struct file *open_file = filesys_open(file);
  if (open_file == NULL) {
    lock_release(&file_lock);
    return -1;
  }

  int fd_idx = thread_current()->fd_count;
  if (fd_idx >= 128) {
    file_close(open_file);
    lock_release(&file_lock);
    return -1;
  }
  thread_current()->fd_count += 1;
    
  //thread_current()->fd[fd_idx] = open_file;
  struct file_info *tmp_file = malloc(sizeof(struct file_info *));
  tmp_file->file = open_file;
  tmp_file->fd = fd_idx;
  list_push_back(&thread_current()->file_list, &tmp_file->elem);
  lock_release(&file_lock);
  return fd_idx;
}

int filesize(int fd)
{
  struct file_info *f_info = search(&thread_current()->file_list, fd);
  struct file *f = f_info->file;
  if (f == NULL)
    exit(-1);
  return file_length(f);
}

void pin(char *start, char *end)
{
  for (int i = start; i < end; i += PGSIZE) {
    struct page *spte = find_spte(i);
    spte->pinned = true;
    if (spte->is_loaded == false)
      handle_page_fault(spte);
  }
}

void unpin(char *start, char *end)
{
  for (int i = start; i < end; i += PGSIZE)
    find_spte(i)->pinned = false;
}


int read(int fd, void *buffer, unsigned size) {
  check_user_address(buffer);
  check_user_address(buffer+size);
  pin(buffer, buffer + size);
  lock_acquire(&file_lock);
  if (fd == 0) {  // stdin
    unsigned idx = 0;
    char w;
    for (; idx < size; idx++) {
      w = input_getc();
      ((char *)buffer)[idx] = w;
      if (w == '\0')
        break;
    }
    unpin(buffer, buffer + size);
    lock_release(&file_lock);
    return idx;
  }
  if (fd == 1) {
    unpin(buffer, buffer + size);
    lock_release(&file_lock);
    return -1;
  }

  // fd != 0, 1
  struct file_info *f_info = search(&thread_current()->file_list, fd);
  struct file *f = f_info->file;
  if (f == NULL) {
    unpin(buffer, buffer + size);
    lock_release(&file_lock);
    return -1;
  }

  int read_size_byte = file_read(f, buffer, size);
  unpin(buffer, buffer + size);
  lock_release(&file_lock);
  return read_size_byte;
}

int write(int fd, const void *buffer, unsigned size) {
  check_user_address(buffer);
  check_user_address(buffer+size);
  pin(buffer, buffer + size);
  lock_acquire(&file_lock);
  //printf("write in +++++++++++++++++++++++++++++++++++++++++\n");
  if (fd == 1) {  // stdout
    putbuf(buffer, size);
    lock_release(&file_lock);
    unpin(buffer, buffer + size);
    return size;
  }
  if (fd == 0) {
    lock_release(&file_lock);
    unpin(buffer, buffer + size);
    return 0;
  }

  // fd != 0, 1
  struct file_info *f_info = search(&thread_current()->file_list, fd);
  struct file *f = f_info->file;
  if (f == NULL)
    return 0;
  
  int write_bytes = file_write(f, buffer, size);
  lock_release(&file_lock);
  unpin(buffer, buffer + size);
  return write_bytes;
}

void seek(int fd, unsigned position) {
  struct file_info *f_info = search(&thread_current()->file_list, fd);
  struct file *f = f_info->file;
  if (f == NULL)
    exit(-1);
  file_seek(f, position);
}

unsigned tell(int fd) {
  struct file_info *f_info = search(&thread_current()->file_list, fd);
  struct file *f = f_info->file;
  if (f == NULL)
    exit(-1);
  return file_tell(f);
}

void close(int fd) {
  struct file_info *f_info = search(&thread_current()->file_list, fd);
  struct file *f = f_info->file;
  if (f == NULL)
    exit(-1);
  //thread_current()->fd[fd] = NULL;
  file_close(f);
  list_remove(&f_info->elem);
  free(f_info);
}

void check_user_address(void *addr) {
  // 포인터가 user 영역 주소를 가리키는지 확인
  if (is_kernel_vaddr(addr) || addr == NULL)
    exit(-1);
}

void get_argument(int *esp, int *args , int count) {
  for (;count > 0; count--) {
    check_user_address(esp);
    esp++;
    check_user_address(esp);
    *args = *esp;
    args++;
  }
}

// 성공 시 map_id 리턴, 실패 시 -1 리턴
int mmap(int fd, void *addr) {
  // addr 시작점이 page 단위 정렬 안 되었을 경우 page 단위로 접근 불가함
  if (addr == NULL || is_kernel_vaddr(addr) || pg_round_down (addr) != addr)
    return -1;

  // memory mapping할 파일 탐색
  struct mmap_file *mmap_file = (struct mmap_file *)malloc(sizeof(struct mmap_file));
  if (mmap_file == NULL)
    return -1;
  memset(mmap_file, 0, sizeof(struct mmap_file));
  list_init(&mmap_file->spte_list);
  struct file_info *f_info = search(&thread_current()->file_list, fd);
  struct file *f = f_info->file;
  if (f == NULL || f_info->fd == 0 || f_info->fd == 1)
    return -1;
  
  // 현재 thread의 mmap_list에 mmap file 추가
  mmap_file->file = file_reopen(f);
  mmap_file->map_id = thread_current()->map_id_count;
  thread_current()->map_id_count += 1;
  list_push_back(&thread_current()->mmap_list, &mmap_file->elem);

  // file을 메모리로 load
  size_t ofs = 0;
  size_t read_bytes = file_length(mmap_file->file);
  if (read_bytes == 0)
    return -1;
  //size_t zero_bytes = PGSIZE - read_bytes % PGSIZE;
  while (read_bytes > 0) {
    if (find_spte(addr) != NULL)
      return -1;

    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    //size_t page_zero_bytes = PGSIZE - page_read_bytes;

    struct page *spte = (struct page *)malloc(sizeof(struct page));
    if (spte == NULL)
      return -1;
    memset(spte, 0, sizeof(struct page));
    spte->type = VM_FILE;
    spte->vaddr = addr;
    spte->write_enable = true;
    spte->file = mmap_file->file;
    spte->offset = ofs;
    spte->read_bytes = page_read_bytes;
    spte->zero_bytes = 0;
    insert_page(&thread_current()->spt, spte);
    list_push_back(&mmap_file->spte_list, &spte->mmap_elem);

    /* Advance. */
    read_bytes -= page_read_bytes;
    //zero_bytes -= page_zero_bytes;
    addr += PGSIZE;
    ofs += page_read_bytes;
  }
  return mmap_file->map_id;
}

void munmap(mapid_t map_id) {
  struct mmap_file *mmap_file = find_mmap_file(map_id);
  if (mmap_file == NULL)
    return;
  
  // mmap_file의 spte_list에 존재하는 모든 spte 제거
  // spte가 물리 페이지에 존재하고, dirty한 경우 disk에 기록
  struct list_elem *e = list_begin(&mmap_file->spte_list);
  while (e != list_end(&mmap_file->spte_list)) {
    struct page *spte = list_entry(e, struct page, mmap_elem);
    if (spte->is_loaded && pagedir_is_dirty(thread_current()->pagedir, spte->vaddr)) {
      lock_acquire(&file_lock);
      file_write_at(spte->file, spte->vaddr, spte->read_bytes, spte->offset);
      lock_release(&file_lock);
      free_frame(pagedir_get_page(thread_current()->pagedir, spte->vaddr));
    }
    spte->is_loaded = false;
    e = list_remove(e);
    delete_page(&thread_current()->spt, spte);
  }

  list_remove(&mmap_file->elem);
  free(mmap_file);
}

// 현재 thread의 mmap_list에서 map_id에 해당하는 mmap file 찾아서 리턴
struct mmap_file *find_mmap_file(int map_id) {
  struct thread *t = thread_current();
  for (struct list_elem *e = list_begin(&t->mmap_list); e != list_end(&t->mmap_list); e = list_next(e)) {
    struct mmap_file *f = list_entry(e, struct mmap_file, elem);
    if (f->map_id == map_id)
      return f;
  }
  return NULL;
}