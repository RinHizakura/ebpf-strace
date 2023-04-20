#ifndef SYSCALL_ENT_H
#define SYSCALL_ENT_H

/* Reference:
 * - https://elixir.bootlin.com/linux/latest/source/include/linux/build_bug.h */
#define static_assert(expr, ...) __static_assert(expr, ##__VA_ARGS__, #expr)
#define __static_assert(expr, msg, ...) _Static_assert(expr, msg)

#define BUF_SIZE 32

typedef struct {
    u64 id;
    u64 ret;
} basic_t;

typedef struct {
    int fd;
    u8 buf[BUF_SIZE];
    size_t count;
} read_args_t;

typedef struct {
    int fd;
    u8 buf[BUF_SIZE];
    size_t count;
} write_args_t;

typedef struct {
    u8 pathname[BUF_SIZE];
    size_t argv;
    size_t envp;
    u8 argc;
    u8 envp_cnt;
} execve_args_t;

typedef struct {
    int status;
} exit_group_args_t;

#endif
