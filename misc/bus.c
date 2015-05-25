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

/*
    int val = 0x12345678;
    ((int *)shared)[1] = val;
    for (i = 0; i < 4; ++i) {
        shared[i] = val & 0xff;
        val >>= 8;
    }
    printf("%x %x %x %x %x\n", shared[0], shared[4], shared[1], shared[5], *(int *)(shared + 2));*/

    int lx = 0;
    while (0) {
        if (shared[0] != lx) {
            lx = shared[0];
            printf("%x\n", lx);
        }
    }

    munmap(shared, TOTAL_SHM_SIZE);
    return 0;
}
