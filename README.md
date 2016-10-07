gdb-heap
========

Forked from https://fedorahosted.org/gdb-heap/ - https://github.com/rogerhu/gdb-heap 

A modified version of gdb-heap with some additional commands to understand heap allocations

See README.old for the original README (do read it)


Load module in GDB
------------------

```
py import sys;sys.path.append("/path/gdb-heap");import gdbheap
```

Commands available
---------------

```
heap - print a report on memory usage, by category
heap sizes - print a report on memory usage, by sizes
heap used - print used heap chunks
heap free - print free heap chunks
heap all - print all heap chunks
heap log - print a log of recorded heap states
heap label - record the current state of the heap for later comparison
heap diff - compare two states of the heap
heap select - query used heap chunks
heap search - Search for address in the heap
heap arenas - print glibs arenas
heap arena <arena> - select glibc arena number
hexdump [-c] [-w] [-s SIZE] <ADDR> - print a hexdump, starting at ADDR
objdump [-v] [-s SIZE] <ADDR> - Consider ADDR as the start of an array of pointers and check if any resolves to a symbol
objsearch [-v] [-s SIZE] - search allocated chunks for possible objects (e.g. blocks containing pointers to mapped files)
```

Examples:
---------

Cool things you can do now (on top of all the cool things you could already do with gdb-heap before)

```
#i know you wanted "!heap -x" from supercool windbg !heap plugin
(gdb) heap search 0x008d721f
search heap for address 0x8d721f
-------------------------------------------------
BLOCK:  0x008d6e00 -> 0x008d721f  inuse:
        1056 bytes (<MChunkPtr chunk=0x8d6e00 mem=0x8d6e10 PREV_INUSE inuse chunksize=1056 memsize=1040>)


# inspired by something similar in the also supercool Corelan's mona.py
(gdb) objdump -s 30 0x0091eaf0

Dumping Object at address 0x91eaf0
-------------------------------------------------
0x91eaf0 => 0x30
0x91eaf8 => 0x191
0x91eb00 => 0x180
0x91eb08 => 0x909298
0x91eb10 => 0x0
0x91eb18 => 0x0
0x91eb20 => 0x91ec98
0x91eb28 => 0x0
0x91eb30 => 0x610000 (/opt/SOMEBINARY)
0x91eb38 => 0x91e4c8
0x91eb40 => 0x0
0x91eb48 => 0x0
0x91eb50 => 0x8e0848
0x91eb58 => 0x0
0x91eb60 => 0x610000 (/opt/SOMEBINARY)
0x91eb68 => 0x0
0x91eb70 => 0x0
0x91eb78 => 0x0
0x91eb80 => 0x0
0x91eb88 => 0x20000000000
0x91eb90 => 0x4010600000088
0x91eb98 => 0x3fffffff00000400
0x91eba0 => 0x91ecf8
0x91eba8 => 0x91ecf9
0x91ebb0 => 0x7ffff6914760 (btreeInvokeBusyHandler.37095 in /opt/SOMELIBRARY.so.1.0.0)
0x91ebb8 => 0x91e2a8
0x91ebc0 => 0x7ffff6878b10 (pageReinit.36734 in /opt/SOMELIBRARY.so.1.0.0)
0x91ebc8 => 0x922bb8
0x91ebd0 => 0xffffffffffffffff
0x91ebd8 => 0x91ebe8

#this was already there, but a few things have changed
(gdb) hexdump 0x8d6980
0x008d6980 -> 0x008d698f 63 72 69 70 74 00 00 00 41 00 00 00 00 00 00 00 |cript...A.......|
0x008d6990 -> 0x008d699f 1c 00 00 00 00 00 00 00 1c 00 00 00 00 00 00 00 |................|
0x008d69a0 -> 0x008d69af 00 00 00 00 00 00 00 00 41 75 74 68 65 6e 74 69 |........Authenti|
0x008d69b0 -> 0x008d69bf 63 61 74 69 6f 6e 20 46 61 69 6c 65 64 20 53 63 |cation Failed Sc|
0x008d69c0 -> 0x008d69cf 72 69 70 74 00 00 00 00 31 00 00 00 00 00 00 00 |ript....1.......|
0x008d69d0 -> 0x008d69df 09 00 00 00 00 00 00 00 09 00 00 00 00 00 00 00 |................|
0x008d69e0 -> 0x008d69ef 00 00 00 00 00 00 00 00 50 61 73 73 77 6f 72 64 |........Password|

```

Useful resources
----------------

 * http://blip.tv/pycon-us-videos-2009-2010-2011/pycon-2011-dude-where-s-my-ram-a-deep-dive-into-how-python-uses-memory-4896725 (Dude - Where's My RAM?  A deep dive in how Python uses memory - David Malcom's PyCon 2011 video talk)

 * http://dmalcolm.fedorapeople.org/presentations/PyCon-US-2011/GdbPythonPresentation/GdbPython.html (David Malcom's PyCon 2011 slides)

 * http://code.woboq.org/userspace/glibc/malloc/malloc.c.html (malloc.c.html implementation)

 * Malloc per-thread arenas in glibc (http://siddhesh.in/journal/2012/10/24/malloc-per-thread-arenas-in-glibc/)

 * Understanding the heap by breaking it (http://www.blackhat.com/presentations/bh-usa-07/Ferguson/Whitepaper/bh-usa-07-ferguson-WP.pdf)
