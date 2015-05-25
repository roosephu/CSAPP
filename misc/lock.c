#include "lock.h"

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
