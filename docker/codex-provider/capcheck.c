#include <errno.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2] = {{0}};

    if (syscall(SYS_capget, &header, data) != 0) {
        return 2;
    }
    if (data[0].effective != 0 || data[1].effective != 0 ||
        data[0].permitted != 0 || data[1].permitted != 0 ||
        data[0].inheritable != 0 || data[1].inheritable != 0) {
        return 1;
    }
    int ambient_supported = 0;
    for (int capability = 0; capability <= CAP_LAST_CAP; capability++) {
        int ambient = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, capability, 0, 0);
        if (ambient == 1) {
            return 1;
        }
        if (ambient == 0) {
            ambient_supported = 1;
        }
        if (ambient < 0 && errno != EINVAL) {
            return 2;
        }
    }
    return ambient_supported ? 0 : 2;
}
