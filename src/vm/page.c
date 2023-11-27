#include "vm/page.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include <string.h>

void page_init (struct hash *page) {
    hash_init(page, page_hash_func, page_less_func, NULL);
}

static unsigned page_hash_func (const struct hash_elem *e, void *aux) {
    return hash_int(hash_entry(e, struct page, helem)->vaddr);
}

static bool page_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux) {
    if (hash_entry(a, struct page, helem)->vaddr < hash_entry(b, struct page, helem)->vaddr)
        return true;
    else
        return false;
}

bool insert_page (struct hash *page, struct page *page_entry) {
    if (hash_insert(page, &page_entry->helem) == NULL)
        return true;
    else
        return false;
}

// swap table 구현 이후 수정 필요
// page(spt entry) 할당 해제 구현 필요
bool delete_page (struct hash *page, struct page *page_entry) {
    if (!hash_delete(page, &page_entry->helem))
        return false;
    free(page_entry);
    return true;
}

struct page *find_spte (void *vaddr) {
    struct hash *page = &thread_current()->spt;
    struct page spte;
    spte.vaddr = pg_round_down(vaddr);
    struct hash_elem *elem = hash_find(page, &spte.helem);
    if (elem) {
        return hash_entry(elem, struct page, helem);
    }
    else {
        return NULL;
    }
}

void page_destroy (struct hash *page) {
    hash_destroy(page, page_destroy_func);
}

// swap table 구현 이후 수정 필요
// page(spt entry) 할당 해제 구현 필요
void page_destroy_func (struct hash_elem *e, void *aux) {
    struct page *spte = hash_entry(e, struct page, helem);
    free(spte);
}

bool load_file (void *kaddr, struct page *spte) {
    size_t bytes = file_read_at(spte->file, kaddr, spte->read_bytes, spte->offset);
    if (bytes != spte->read_bytes) {
        return false;
    }
    else {
        return true;
    }
}

void check_valid_buffer (void *buffer, unsigned size, void *esp, bool to_write) {
    for (int i = 0; i < size; i++) {
        struct page* spte = check_user_address(buffer + i);
        if(spte == NULL || (to_write == true && spte->write_enable == false))
            exit(-1);
    }
}
