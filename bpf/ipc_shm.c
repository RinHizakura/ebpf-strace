static void sys_shmget_enter(syscall_ent_t *ent, struct input_parms parms)
{
    key_t key = parms.parm1;
    size_t size = parms.parm2;
    int shmflg = parms.parm3;

    shmget_args_t *shmget = (shmget_args_t *) ent->bytes;

    shmget->key = key;
    shmget->size = size;
    shmget->shmflg = shmflg;
}

static void sys_shmat_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int shmid = parms.parm1;
    void *shmaddr = (void *) parms.parm2;
    int shmflg = parms.parm3;

    shmat_args_t *shmat = (shmat_args_t *) ent->bytes;

    shmat->shmid = shmid;
    shmat->shmaddr = shmaddr;
    shmat->shmflg = shmflg;
}

static void sys_shmctl_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int shmid = parms.parm1;
    int cmd = parms.parm2;
    shmid_ds_t *buf = (shmid_ds_t *) parms.parm3;

    shmctl_args_t *shmctl = (shmctl_args_t *) ent->bytes;

    shmctl->shmid = shmid;
    shmctl->cmd = cmd;
    shmctl->buf_addr = buf;
}

static void sys_shmctl_exit(syscall_ent_t *ent)
{
    shmctl_args_t *shmctl = (shmctl_args_t *) ent->bytes;
    void *buf = shmctl->buf_addr;

    if (buf != NULL) {
        /* TODO: Let's consider IPC_INFO and SHM_INFO */
        bpf_core_read_user(&shmctl->buf, sizeof(shmid_ds_t), buf);
    }
}
