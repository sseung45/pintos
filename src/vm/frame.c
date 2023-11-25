#include "vm/frame.h"
#include "threads/synch.h"

struct list frame_list;
struct lock frame_lock;
struct list_elem *clock_ptr;

void frame_init (void) {
    list_init(&frame_list);
    lock_init(&frame_lock);
    clock_ptr = NULL;
}

void insert_frame (struct frame *frame) {
    lock_acquire(&frame_lock);
    list_push_back(&frame_list, &frame->elem);
    lock_release(&frame_lock);
}

void delete_frame (struct frame *frame) {
    ASSERT (lock_held_by_current_thread(&frame_lock));
    if (clock_ptr == &frame->elem)
        clock_ptr = list_remove(&frame->elem);
    else
        list_remove(&frame->elem);
}

static struct list_elem *get_next_clock_ptr (void) {
    ASSERT (lock_held_by_current_thread(&frame_lock));
    if (clock_ptr == NULL)
        return NULL;

    if (clock_ptr == list_end(&frame_list))
        clock_ptr = list_begin(&frame_list);
    else
        clock_ptr = list_next(clock_ptr);
    
    return clock_ptr;
}


struct frame *alloc_frame (enum palloc_flags flag) {
    
}

void free_frame (void *kaddr) {
    
}
