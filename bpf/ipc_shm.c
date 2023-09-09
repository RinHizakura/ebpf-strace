
static void sys_shmget_enter(syscall_ent_t *ent,
                             key_t key,
                             size_t size,
                             int shmflg)
{
    shmget_args_t *shmget = (shmget_args_t *) ent->bytes;

    shmget->key = key;
    shmget->size = size;
    shmget->shmflg = shmflg;
}

static void sys_shmat_enter(syscall_ent_t *ent,
                            int shmid,
                            void *shmaddr,
                            int shmflg)
{
    shmat_args_t *shmat = (shmat_args_t *) ent->bytes;

    shmat->shmid = shmid;
    shmat->shmaddr = shmaddr;
    shmat->shmflg = shmflg;
}

static void sys_shmctl_enter(syscall_ent_t *ent, int cmd, struct shmid_ds *buf)
{
    shmctl_args_t *shmctl = (shmctl_args_t *) ent->bytes;

    shmctl->cmd = cmd;
    if (buf)
        bpf_core_read_user(&shmctl->buf, sizeof(struct shmid_ds), buf);
}
