from random import *

with open("final.ys", "w") as f :
    print >> f, "  .pos 0"
    print >> f, "  irmovl 0x4000, %%eax"
    print >> f, "  irmovl %%ecx, (%%eax)"
    print >> f, "  nop"
    print >> f
