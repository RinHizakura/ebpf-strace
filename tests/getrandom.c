#include <stdio.h>
#include <sys/random.h>

int main()
{
    char buf[16];
    long ret = getrandom(buf, sizeof(buf), 0);
    if (ret < 0) {
        puts("+++ exited with 0 +++");
        return -1;
    }
    printf("getrandom(%zu, 0) = %ld\n", sizeof(buf), ret);

    puts("+++ exited with 0 +++");
    return 0;
}
