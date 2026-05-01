static void sys_setpgid_enter(syscall_ent_t *ent, struct input_parms parms)
{
    pid_t pid = (pid_t) parms.parm1;
    pid_t pgid = (pid_t) parms.parm2;

    setpgid_args_t *setpgid = (setpgid_args_t *) ent->bytes;
    setpgid->pid = pid;
    setpgid->pgid = pgid;
}

static void sys_getpgid_enter(syscall_ent_t *ent, struct input_parms parms)
{
    pid_t pid = (pid_t) parms.parm1;

    getpgid_args_t *getpgid = (getpgid_args_t *) ent->bytes;
    getpgid->pid = pid;
}

static void sys_getsid_enter(syscall_ent_t *ent, struct input_parms parms)
{
    pid_t pid = (pid_t) parms.parm1;

    getsid_args_t *getsid = (getsid_args_t *) ent->bytes;
    getsid->pid = pid;
}
