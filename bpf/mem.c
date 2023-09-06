static void sys_mmap_enter(syscall_ent_t *ent,
                           void *addr,
                           size_t length,
                           int prot,
                           int flags,
                           int fd,
                           off_t offset)
{
    mmap_args_t *mmap = (mmap_args_t *) ent->bytes;

    mmap->addr = addr;
    mmap->length = length;
    mmap->prot = prot;
    mmap->flags = flags;
    mmap->fd = fd;
    mmap->offset = offset;
}

static void sys_mprotect_enter(syscall_ent_t *ent,
                               void *addr,
                               size_t len,
                               int prot)
{
    mprotect_args_t *mprotect = (mprotect_args_t *) ent->bytes;

    mprotect->addr = addr;
    mprotect->len = len;
    mprotect->prot = prot;
}

static void sys_munmap_enter(syscall_ent_t *ent, void *addr, size_t length)
{
    munmap_args_t *munmap = (munmap_args_t *) ent->bytes;
    munmap->addr = addr;
    munmap->length = length;
}

static void sys_brk_enter(syscall_ent_t *ent, void *addr)
{
    brk_args_t *brk = (brk_args_t *) ent->bytes;
    brk->addr = addr;
}

static void sys_mremap_enter(syscall_ent_t *ent,
                             void *old_address,
                             size_t old_size,
                             size_t new_size,
                             int flags,
                             void *new_address)
{
    mremap_args_t *mremap = (mremap_args_t *) ent->bytes;

    mremap->old_address = old_address;
    mremap->old_size = old_size;
    mremap->new_size = new_size;
    mremap->flags = flags;
    /* This member is valid only for specific flags. Here we just fill it
     * with the possible value and ensure it at userspace program. */
    mremap->new_address = new_address;
}

static void sys_msync_enter(syscall_ent_t *ent,
                            void *addr,
                            size_t length,
                            int flags)
{
    msync_args_t *msync = (msync_args_t *) ent->bytes;

    msync->addr = addr;
    msync->length = length;
    msync->flags = flags;
}
