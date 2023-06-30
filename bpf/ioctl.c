#define _IOC_NRBITS 8
#define _IOC_TYPEBITS 8
#define _IOC_SIZEBITS 14
#define _IOC_DIRBITS 2

#define _IOC_NRMASK ((1 << _IOC_NRBITS) - 1)
#define _IOC_TYPEMASK ((1 << _IOC_TYPEBITS) - 1)
#define _IOC_SIZEMASK ((1 << _IOC_SIZEBITS) - 1)
#define _IOC_DIRMASK ((1 << _IOC_DIRBITS) - 1)

#define _IOC_NRSHIFT 0
#define _IOC_TYPESHIFT (_IOC_NRSHIFT + _IOC_NRBITS)
#define _IOC_SIZESHIFT (_IOC_TYPESHIFT + _IOC_TYPEBITS)
#define _IOC_DIRSHIFT (_IOC_SIZESHIFT + _IOC_SIZEBITS)

#define _IOC_DIR(nr) (((nr) >> _IOC_DIRSHIFT) & _IOC_DIRMASK)

#define _IOC_NONE 0
#define _IOC_WRITE 1
#define _IOC_READ 2

static void sys_ioctl_enter(syscall_ent_t *ent,
                            int fd,
                            unsigned long request,
                            void *arg)
{
    ioctl_args_t *ioctl = (ioctl_args_t *) ent->bytes;
    ioctl->fd = fd;
    ioctl->request = request;
    ioctl->arg = (unsigned long) arg;
}

static void sys_ioctl_exit(syscall_ent_t *ent)
{
    ioctl_args_t *ioctl = (ioctl_args_t *) ent->bytes;
    void *p = (void *) ioctl->arg;
    switch (_IOC_DIR(ioctl->request)) {
    case _IOC_READ:
        if (p)
            bpf_core_read_user(&ioctl->arg, sizeof(unsigned long), p);
        break;
    case _IOC_WRITE:
    case _IOC_NONE:
    default:
        break;
    }
}
