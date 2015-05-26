#include "lock.h"

#define cerr(...) fprintf(stderr, __VA_ARGS__)

int fd[3], own;

void lock_init() {
    // fd[0] = open(LOCK_FN_A     , O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    fd[1] = open(LOCK_FN_B     , O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
}

bool_t lock() {
    int res = flock(fd[1], LOCK_EX | LOCK_NB) == 0;
    cerr("--- acquire lock: %s ---\n", res ? "YES" : "NO");
    return res;
    // flock(fd[0], LOCK_UN);
}

void unlock() {
    int res = flock(fd[1], LOCK_UN) == 0;
    cerr("--- release lock: %s ---\n", res ? "YES" : "NO");
    // flock(fd[0], LOCK_EX);
}
