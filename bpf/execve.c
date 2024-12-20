static size_t count_envp_len(char *arr[])
{
    size_t idx = 0;
    if (arr != NULL) {
        for (; idx < LOOP_MAX; idx++) {
            char *var = NULL;
            bpf_core_read_user(&var, sizeof(var), &arr[idx]);
            if (!var)
                break;
        }
    }

    return idx;
}

static void sys_execve_enter(syscall_ent_t *ent, struct input_parms parms)
{
    char *pathname = (char *) parms.parm1;
    char **argv = (void *) parms.parm2;
    char **envp = (void *) parms.parm3;

    execve_args_t *execve = (execve_args_t *) ent->bytes;

    /* FIXME: In the current design of entry format under the
     * syscall_record ring buffer, we have to bring all the
     * information(parameters, return value, ...) in one entry
     * per syscall. However, we cannot increase the entry size endlessly
     * for the system call like execve which has so many string type
     * parameters, otherwise we'll waste too many space when passing
     * those system calls which only need a few bytes for the parameters.
     *
     * We should redesign the entry format to fix this problem. */
    size_t idx = 0;
    for (; idx < LOOP_MAX; idx++) {
        char *var = NULL;
        bpf_core_read_user(&var, sizeof(var), &argv[idx]);
        if (!var)
            break;

        if (idx < ARR_ENT_SIZE) {
            memset(execve->argv[idx], 0, BUF_SIZE);
            bpf_core_read_user(execve->argv[idx], BUF_SIZE, var);
        }
    }
    execve->argc = idx;

    execve->envp = (size_t) envp;
    execve->envp_cnt = count_envp_len(envp);

    memset(execve->pathname, 0, sizeof(execve->pathname));
    bpf_core_read_user(execve->pathname, sizeof(execve->pathname), pathname);
}
