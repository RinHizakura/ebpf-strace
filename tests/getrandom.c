#include <stdio.h>
#include <string.h>
#include <sys/random.h>

static void format_buf(const char *buf, size_t len, char *out, size_t out_sz)
{
    size_t pos = 0;
    pos += snprintf(out + pos, out_sz - pos, "\"");
    for (size_t i = 0; i < len && pos < out_sz - 6; i++) {
        unsigned char c = (unsigned char) buf[i];
        if (c == '\\') {
            pos += snprintf(out + pos, out_sz - pos, "\\\\");
        } else if (c == '"') {
            pos += snprintf(out + pos, out_sz - pos, "\\\"");
        } else {
            pos += snprintf(out + pos, out_sz - pos, "\\x%02x", c);
        }
    }
    pos += snprintf(out + pos, out_sz - pos, "\"");
    out[pos] = '\0';
}

int main()
{
    char buf[16];
    long ret = getrandom(buf, sizeof(buf), 0);
    if (ret < 0) {
        puts("+++ exited with 0 +++");
        return -1;
    }
    char buf_str[128];
    format_buf(buf, (size_t) ret, buf_str, sizeof(buf_str));
    printf("getrandom(%s, %zu, 0) = %ld\n", buf_str, sizeof(buf), ret);

    puts("+++ exited with 0 +++");
    return 0;
}
