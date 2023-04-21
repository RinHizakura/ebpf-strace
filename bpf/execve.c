static size_t count_argc_envp_len(char *arr[])
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

static void sys_execve_enter(syscall_ent_t *ent,
                             u64 id,
                             char *pathname,
                             char *argv[],
                             char *envp[])
{
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
    execve->argv = (size_t) argv;
    execve->argc = count_argc_envp_len(argv);

    execve->envp = (size_t) envp;
    execve->envp_cnt = count_argc_envp_len(envp);

    memset(execve->pathname, 0, sizeof(execve->pathname));
    bpf_core_read_user_str(execve->pathname, sizeof(execve->pathname),
                           pathname);
}
