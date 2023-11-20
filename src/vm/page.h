#include <list.h>
#include <hash.h>

#define VM_BIN 0
#define VM_FILE 1
#define VM_ANON 2

struct page {
    int type;
    void *vaddr;
    bool write_enable;
    struct file* file;
    struct list_elem fmmap_list;
    size_t offset;
    size_t read_bytes;
    size_t zero_bytes;
    size_t swap_table;
    struct hash_elem helem;
};

void page_init (struct hash *page);
static int page_hash_val (struct hash_elem *e, void *aux);
static bool page_isless_val (struct hash_elem *a, struct hash_elem *b, void *aux);