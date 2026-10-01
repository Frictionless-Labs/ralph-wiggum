#include <linux/capability.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2] = {{0}};

    if (syscall(SYS_capget, &header, data) != 0) {
        return 2;
    }
    return (data[0].effective != 0 || data[1].effective != 0) ? 1 : 0;
}
