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
