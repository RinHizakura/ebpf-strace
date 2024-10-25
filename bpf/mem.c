static void sys_mmap_enter(syscall_ent_t *ent, struct input_parms parms)
{
    void *addr = (void *) parms.parm1;
    size_t length = parms.parm2;
    int prot = parms.parm3;
    int flags = parms.parm4;
    int fd = parms.parm5;
    off_t offset = parms.parm6;

    mmap_args_t *mmap = (mmap_args_t *) ent->bytes;

    mmap->addr = addr;
    mmap->length = length;
    mmap->prot = prot;
    mmap->flags = flags;
    mmap->fd = fd;
    mmap->offset = offset;
}

static void sys_mprotect_enter(syscall_ent_t *ent, struct input_parms parms)
{
    void *addr = (void *) parms.parm1;
    size_t len = parms.parm2;
    int prot = parms.parm3;

    mprotect_args_t *mprotect = (mprotect_args_t *) ent->bytes;

    mprotect->addr = addr;
    mprotect->len = len;
    mprotect->prot = prot;
}

static void sys_munmap_enter(syscall_ent_t *ent, struct input_parms parms)
{
    void *addr = (void *) parms.parm1;
    size_t length = parms.parm2;

    munmap_args_t *munmap = (munmap_args_t *) ent->bytes;
    munmap->addr = addr;
    munmap->length = length;
}

static void sys_brk_enter(syscall_ent_t *ent, struct input_parms parms)
{
    void *addr = (void *) parms.parm1;

    brk_args_t *brk = (brk_args_t *) ent->bytes;
    brk->addr = addr;
}

static void sys_mremap_enter(syscall_ent_t *ent, struct input_parms parms)
{
    void *old_address = (void *) parms.parm1;
    size_t old_size = parms.parm2;
    size_t new_size = parms.parm3;
    int flags = parms.parm4;
    void *new_address = (void *) parms.parm5;

    mremap_args_t *mremap = (mremap_args_t *) ent->bytes;

    mremap->old_address = old_address;
    mremap->old_size = old_size;
    mremap->new_size = new_size;
    mremap->flags = flags;
    /* This member is valid only for specific flags. Here we just fill it
     * with the possible value and ensure it at userspace program. */
    mremap->new_address = new_address;
}

static void sys_msync_enter(syscall_ent_t *ent, struct input_parms parms)
{
    void *addr = (void *) parms.parm1;
    size_t length = parms.parm2;
    int flags = parms.parm3;

    msync_args_t *msync = (msync_args_t *) ent->bytes;

    msync->addr = addr;
    msync->length = length;
    msync->flags = flags;
}

static void sys_mincore_enter(syscall_ent_t *ent, struct input_parms parms)
{
    void *addr = (void *) parms.parm1;
    size_t length = parms.parm2;
    unsigned char *vec = (unsigned char *) parms.parm3;

    mincore_args_t *mincore = (mincore_args_t *) ent->bytes;

    mincore->addr = addr;
    mincore->length = length;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = vec;
}

static void sys_mincore_exit(syscall_ent_t *ent)
{
    mincore_args_t *mincore = (mincore_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    /* FIXME: Get the page shift reasonably instead of using the hardcoded one.
     */
    size_t page_shift = 12;
    size_t page_mask = (1 << page_shift) - 1;
    size_t nmemb = (mincore->length + page_mask) >> page_shift;

    size_t cpy_count =
        (nmemb > ARR_ENT_SIZE ? ARR_ENT_SIZE : nmemb) * sizeof(unsigned char);
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(mincore->vec, cpy_count, *buf_addr_ptr);
}

static void sys_madvise_enter(syscall_ent_t *ent, struct input_parms parms)
{
    void *addr = (void *) parms.parm1;
    size_t length = parms.parm2;
    int advice = parms.parm3;

    madvise_args_t *madvise = (madvise_args_t *) ent->bytes;

    madvise->addr = addr;
    madvise->length = length;
    madvise->advice = advice;
}
