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
