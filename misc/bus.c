#include <fcntl.h>
#include <assert.h>
#include <stdio.h>
#include <sys/mman.h>
#include "isa.h"

int main() {
    int fd = open(SHARED_FILE, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    assert(fd != -1);

    lseek(fd, SHARED_MEM_POS, SEEK_SET);
    write(fd, "a", 1);
    lseek(fd, 0, SEEK_SET);

    byte_t *shared = mmap(NULL, SHARED_MEM_POS, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FILE, fd, 0);
    assert(shared != MAP_FAILED);
    close(fd);

    int i;
    for (i = 0; i < SHARED_MEM_POS; ++i)
        shared[i] = 0;

    int lx = 0;
    while (1) {
        if (shared[0] != lx) {
            lx = shared[0];
            printf("%d\n", lx);
        }
    }

    munmap(shared, 10);
    return 0;
}
