#ifndef MACRO_LOCK
#define MACRO_LOCK
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/file.h>
#include "isa.h"

#define LOCK_FN_A "/tmp/y86-lock-A"
#define LOCK_FN_B "/tmp/y86-lock-B"
#define LOCK_FN_COMMON "/tmp/y86-lock-run"

void lock_init();
bool_t lock();
void unlock();
#endif
