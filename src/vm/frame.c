#include "vm/frame.h"
#include "threads/synch.h"
#include "lib/kernel/bitmap.h"
#include "devices/block.h"

struct list frame_list;
struct lock frame_lock;
struct list_elem *clock_ptr;

struct lock swap_lock;
struct bitmap *swap_table;
struct block *swap_disk;
size_t swap_slot_count;

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

void swap_init(void){
    swap_disk = block_get_role(BLOCK_SWAP);
    lock_init(&swap_lock);
    swap_slot_count = block_size(swap_disk) / 8; //sector size = 512 B, slot size = 4 KB. 따라서 slot 하나당 sector 8개
    swap_table = bitmap_create(swap_slot_count);
}

void swap_in(size_t used_index, void* kaddr){
    lock_acquire(&swap_lock);

    size_t index_sector = used_index * 8;
    void* buf = kaddr;

    for(int i = 0; i < 8; i++){
        block_read(swap_disk, index_sector, buf);
        index_sector++;
        buf += BLOCK_SECTOR_SIZE;
    }

    bitmap_set(swap_table, used_index, 0);

    lock_release(&swap_lock);
}

size_t swap_out(void* kaddr){
    lock_acquire(&swap_lock);

    size_t index_empty = bitmap_scan_and_flip(swap_table, 0, 1, 0);
    if(index_empty == BITMAP_ERROR || index_empty >= swap_slot_count) //error
        return BITMAP_ERROR;

    size_t index_sector = index_empty * 8;
    void* buf = kaddr;

    for(int i = 0; i < 8; i++){
        block_write(swap_disk, index_sector, buf);
        index_sector++;
        buf += BLOCK_SECTOR_SIZE;
    }

    lock_release(&swap_lock);

    return index_empty;
}