# Document for my CSAPP experiment

## some assumptions
The memory is partitioned into 3 parts:

+ 0x0000 to 0x4000: private memory. Code and stack are stored in this part.
+ 0x4000 to 0xC000: shared memory. The message between two Y86 code is put on this part.
+ 0xC000 to 0x10000: shared memory. For communication of two simulator with bus (to archieve cache coherence).

## implementation for bus
Only 4 words in bus are needed.

+ 1: the total number of clients which have started now. Each client gets an ID from this word.
+ 2: the broadcast message.
+ 3: the state of clients responding to broadcast.
+ 4: the state of clients which have left.

The only work for bus is to watch the third word.
When this word indicates all clients have responded, the bus clears the broadcast message.

## main idea
The core idea is that: before we access the main memory, we need to broadcast our operation and wait for response.

To broadcast a message, the procedure is:

+ the client that wants to broadcast: set the second word in bus to the desired message and clears the third word, and wait it to be 0 (i.e., an invalid message).
+ the other clients: check whether there is a broadcast sometimes, and respond it if so. The response needs to modify the third byte in the bus.
+ the bus: check the third word and wait until all clients have responded, then clear broadcast message.

To avoid two clients broadcasting at the same, we introduce a `lock`. When an clients needs to operate main memory, it needs to acquire a lock before actually doing it. After the operation has been done, the lock should be released. If the client is waiting for a lock, it should respond to the broadcast.

To avoid starvation, each client should try to respond at the beginning of a cycle.

## broadcast and respond
Broadcast and respond are two core concept of this program.

If a simulator needs to access memory (no matter R/W), it needs to `broadcast` its operation.
The `broadcast` message contains 3 parts: ID part, type part, and pos part.

1. The pos part is the last 16 bit, indicating the destination of this operation.
2. The type part is the next 8 bit. Only two types are needed: `R` or `W`
3. The ID part is the next 8 bit, indicating the owner of this broadcast.

If one simulator finds there is a broadcast, it needs to `respond` to this broadcast.
The `reponse` is that:

1. If the type of the broadcast is `R`, the client needs to check corresponding cache and commit it to main memory if necessary, by looking up its `D` bit.
2. If the type of the broadcast is `W`, the client needs to commit the corresponding cache if necessary, and then invalidate the cache.

## some details

### how to open a shared memory

```c
int fd = open(SHARED_FILE, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
byte_t shared_ptr = mmap(NULL, TOTAL_SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FILE, fd, 0);
```

### how to acquire/release lock

We introduce a file lock here since it's atomic.

```c
bool_t lock(mem_t mem) {
    while (flock(fd[1], LOCK_EX | LOCK_NB) != 0) { // acquiring a lock
        response(mem);                             // respond to the current broadcast, otherwise deadlock may come
        usleep(SLEEP_USEC);
    }
    return TRUE;
}

void unlock() {
    flock(fd[1], LOCK_UN);
}
```

### how the bus works

``` c
for ( ; bus[4] != (mask << 1); usleep(33)) {        // if at least one client survives
    int broadcast = bus[1];
    if (BROADCAST_TYPE(broadcast) != 0) {           // there is a valid broadcast
        for ( ; (bus[3] | bus[4]) != (mask << 1); ) // some clients haven't reponded to this broadcast
            usleep(3);
        bus[1] = 0;                                 // clear broadcast
    }
}
```

### how to broadcast

```c
void broadcast(mem_t mem, int type, int addr) {
    if (addr < SHARED_MEM_POS)                              // we only need to broadcast message for operations on shared memory
        return ;

    int value = PACK_BROADCAST(my_id, type, addr);          // the broadcast message
    int *bus = (int *)(mem->aux->shared + SHARED_MEM_SIZE);

    bus[1] = value, bus[3] = 1 << my_id;                    // note that we must have acquired lock
    for ( ; BROADCAST_TYPE(bus[1]) != 0; )                  // every client must respond to me
        usleep(SLEEP_USEC);
    usleep(SLEEP_USEC);
}
```

### how to respond

```c
bool_t response(mem_t mem) {
    int *bus = (int *)(mem->aux->shared + SHARED_MEM_SIZE);

    int broadcast = bus[1];                                      // the broadcast message
    word_t type = BROADCAST_TYPE(broadcast);
    word_t addr = BROADCAST_ADDR(broadcast);
    if (type == 0)                                               // an invalid broadcast
        return FALSE;
    if ((bus[3] >> my_id) != 1) {                                // if we haven't responded to it.
        assert(addr >= SHARED_MEM_POS);
        cache_blk_t blk = find_cache_blk(mem->aux->cache, addr);

        if (blk != NULL) {
            if (IS_DIRTY(blk))                                   // if we have modified it, commit it
                commit_cache(mem, blk, addr);
            if (type == 'W') {                                   // if the type is W, we need to invalidate the cache
                SET_INVALID(blk);
            }
        }
        bus[3] |= 1 << my_id;                                    // mark that we have responded it
    }
    return TRUE;
}
```
