#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "vm/page.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

bool handle_page_fault (struct page *spte);
struct mmap_file *find_mmap_file(int map_id);

bool stack_growth(void *addr);

#endif /* userprog/process.h */
