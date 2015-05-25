
#ifndef MACRO_LOCK
#define MACRO_LOCK
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/file.h>

#define LOCK_FN_A "X"
#define LOCK_FN_B "Y"
#define LOCK_FN_COMMON "/tmp/y86-lock-run"

void lock_init();
void lock();
void unlock();
#endif

int fd[3], own;

void lock_init() {
    fd[0] = open(LOCK_FN_A     , O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    fd[1] = open(LOCK_FN_B     , O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
}

void lock() {
    flock(fd[1], LOCK_EX);
    flock(fd[0], LOCK_UN);
}

void unlock() {
    flock(fd[1], LOCK_UN);
    flock(fd[0], LOCK_EX);
}

int main() {
    int x = 0;
    lock_init();
    lock();
    printf("....\n");
    sleep(10);
    unlock();
    /*while (1) {
        lock();
        sleep(1);
        ++x;
        printf("%d\n", x);
        unlock();
    }*/
    return 0;
}
