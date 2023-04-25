#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

void do_file_operation()
{
    long fd = syscall(SYS_open, "README.md", O_RDONLY);
    syscall(SYS_close, fd);
}

int main()
{
    do_file_operation();
    return 0;
}
