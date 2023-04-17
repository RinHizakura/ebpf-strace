#ifndef SYSCALL_ENT_H
#define SYSCALL_ENT_H

/* Reference:
 * - https://elixir.bootlin.com/linux/latest/source/include/linux/build_bug.h */
#define static_assert(expr, ...) __static_assert(expr, ##__VA_ARGS__, #expr)
#define __static_assert(expr, msg, ...) _Static_assert(expr, msg)

#define BUF_SIZE 32

typedef struct {
    u8 args[64];
} args_t;

typedef struct {
    int fd;
    u8 buf[BUF_SIZE];
    size_t count;
} read_args_t;
static_assert(sizeof(read_args_t) <= sizeof(args_t));

typedef struct {
    int fd;
    u8 buf[BUF_SIZE];
    size_t count;
} write_args_t;
static_assert(sizeof(write_args_t) <= sizeof(args_t));

typedef struct {
    int status;
} exit_group_args_t;
static_assert(sizeof(exit_group_args_t) <= sizeof(args_t));

/* FIXME: This structure is designed to be used in
 * both C and Rust. However, this is not pretty :( */
typedef struct {
    u64 id;
    u64 ret;

    union {
        /* Note: We should make sure that args_t is the
         * largest struct under the union. This guarantee
         * the structure layout between C and Rust code. */
        args_t args;
        read_args_t read;
        write_args_t write;
        exit_group_args_t exit_group;
    };
} syscall_ent_t;

#endif
