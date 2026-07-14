// Host-native disposable fixture for the Auto Enum port adaptation.
// Build with: cc -O0 -g auto_enum_port_host.c -o <temporary-output>

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int fd = open("/tmp/idax-auto-enum-missing", O_RDONLY);
    int socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int option = 1;
    (void)setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR,
                     &option, sizeof(option));

    void *region = mmap(0, 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANON, -1, 0);
    if (region != MAP_FAILED) {
        (void)mprotect(region, 4096, PROT_READ);
        (void)munmap(region, 4096);
    }

    (void)access("/tmp", R_OK);
    if (socket_fd >= 0)
        (void)close(socket_fd);
    if (fd >= 0)
        (void)close(fd);
    return 0;
}
