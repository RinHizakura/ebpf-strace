#include <stdio.h>
#include <sys/resource.h>

static void fmt_rlim(unsigned long long v, char *buf, size_t sz)
{
    if (v == (unsigned long long) RLIM_INFINITY)
        snprintf(buf, sz, "RLIM_INFINITY");
    else
        snprintf(buf, sz, "%llu", v);
}

int main()
{
    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim) < 0)
        goto end;
    if (setrlimit(RLIMIT_NOFILE, &rlim) < 0)
        goto end;
    char cur[32], max[32];
    fmt_rlim((unsigned long long) rlim.rlim_cur, cur, sizeof(cur));
    fmt_rlim((unsigned long long) rlim.rlim_max, max, sizeof(max));
    printf("setrlimit(RLIMIT_NOFILE, {rlim_cur=%s, rlim_max=%s}) = 0\n", cur,
           max);
end:
    puts("+++ exited with 0 +++");
    return 0;
}
