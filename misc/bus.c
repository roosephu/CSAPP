#include <fcntl.h>
#include <assert.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include "isa.h"

int main()
{
    int fd = open(SHARED_FILE, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    assert(fd != -1);

    byte_t zeros[TOTAL_SHM_SIZE] = {0};
    write(fd, zeros, sizeof zeros);

    byte_t *shared = mmap(NULL, TOTAL_SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FILE, fd, 0);
    assert(shared != MAP_FAILED);
    close(fd);

    int i;
    for (i = 0; i < TOTAL_SHM_SIZE; ++i)
        shared[i] = 0;

    int lx = 0;
    while (1) {
        if (shared[0] != lx) {
            lx = shared[0];
            printf("%x\n", lx);
        }
    }

    munmap(shared, 10);
    return 0;
}
