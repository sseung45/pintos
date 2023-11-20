#include <page.h>
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

void page_init (struct hash *page) {
    hash_init(page, page_hash_func, page_less_func, NULL);
}

static int page_hash_func (struct hash_elem *e, void *aux) {
    return hash_int(hash_entry(e, struct page, helem)->vaddr);
}

static bool page_less_func (struct hash_elem *a, struct hash_elem *b, void *aux) {
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
    if (elem)
        return hash_entry(elem, struct page, helem);
    else
        return NULL;
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