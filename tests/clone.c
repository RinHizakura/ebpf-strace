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
    printf("clone(child_stack=NULL, flags=SIGCHLD) = %d\n", child);
    waitpid(child, NULL, 0);
end:
    puts("+++ exited with 0 +++");
    return 0;
}
