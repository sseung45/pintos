#include <page.h>

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