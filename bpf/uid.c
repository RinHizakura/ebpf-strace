static void sys_setuid_enter(syscall_ent_t *ent, struct input_parms parms)
{
    uid_t uid = (uid_t) parms.parm1;

    setuid_args_t *setuid = (setuid_args_t *) ent->bytes;
    setuid->uid = uid;
}

static void sys_setgid_enter(syscall_ent_t *ent, struct input_parms parms)
{
    gid_t gid = (gid_t) parms.parm1;

    setgid_args_t *setgid = (setgid_args_t *) ent->bytes;
    setgid->gid = gid;
}
