#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <page.h>
#include "threads/thread.h"
#include "threads/palloc.h"

struct frame {
    void *kaddr;
    struct page *spte;
    struct thread *t;
    struct list_elem elem;
};

void frame_init (void);
void insert_frame (struct frame *frame);
void delete_frame (struct frame *frame);
struct frame *alloc_frame(enum palloc_flags flag);
void free_frame(void *kaddr);
static struct list_elem *get_next_clock_ptr(void);

#endif