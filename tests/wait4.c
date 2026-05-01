#include <signal.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main()
{
    pid_t child = syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0);
    if (child < 0)
        goto end;
    if (child == 0)
        _exit(0);
    int wstatus = 0;
    pid_t ret = wait4(-1, &wstatus, 0, NULL);
    if (ret < 0)
        goto end;
    printf("wait4(-1, [{wstatus=%d}], 0, NULL) = %d\n", wstatus, (int) ret);
end:
    puts("+++ exited with 0 +++");
    return 0;
}
