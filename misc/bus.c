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

    ftruncate(fd, 0);
    byte_t zeros[TOTAL_SHM_SIZE] = {0};
    write(fd, zeros, sizeof(zeros));

    byte_t *shared = mmap(NULL, TOTAL_SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FILE, fd, 0);
    assert(shared != MAP_FAILED);
    close(fd);

    int i;
    for (i = 0; i < TOTAL_SHM_SIZE; ++i)
        shared[i] = 0;
    printf("Memory size: 0x%x\n", TOTAL_SHM_SIZE);

    int *bus = (int *)(shared + SHARED_MEM_SIZE);

    int clients = 2;
    printf("Waiting for %d client(s)...\n", 2);
    for (; bus[0] != clients; )
        usleep(50);

    int mask = (1 << clients) - 1;

    printf("Clients ready...\n");

    for ( ; bus[4] != (mask << 1); usleep(33)) {
        int broadcast = bus[1];
        if (broadcast != 0) {
            printf("Find a broadcast...0x%.8x\n", broadcast);
            for ( ; (bus[3] | bus[4]) != (mask << 1); )
                usleep(3);
            bus[2] = 1;
        }
    }
    printf("Clients have already exited...\n");
    for (i = 0; i < SHARED_MEM_SIZE; ++i) {
        if (shared[i] != 0) {
            printf("Final 0x%.4x: 0x%.8x\n", i, shared[i]);
        }
    }

/*
    int val = 0x12345678;
    ((int *)shared)[1] = val;
    for (i = 0; i < 4; ++i) {
        shared[i] = val & 0xff;
        val >>= 8;
    }
    printf("%x %x %x %x %x\n", shared[0], shared[4], shared[1], shared[5], *(int *)(shared + 2));*/

    munmap(shared, TOTAL_SHM_SIZE);
    return 0;
}
