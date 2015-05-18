# main ideas
Bus is a fifo. Since the simulator runs step by step, we can perform checking before 

The coherence strategy is: before any operations to MEM, ask bus for reply OK. It should also monitor the `B/W` messages.

## how to monitor bus
At the end of the transition, check the fifo.  
The one waiting for reply must runs in a loop to check a bit in the memory. 

## how to reply bus
Reply `Y` if nothing happens.  

## format for connecting with bus
1. `R[addr]`: read
2. `W[addr]`: write
3. `B[byte]`: new byte
4. `W[word]`: new word
5. `O`: by bus
6. `Y`: by client, means OK.

## what bus should do
Bus collects the information from clients and sends `O` so that the request one can stop monitoring.

## more precise strategy
+ read:
    + hit: just read from cache
    + miss: broadcast `R`, waiting for `B/W` and go on if `O` is received
+ write:
    + hit: just write to cache 
    + miss: broadcast `W`, waiting for `O`