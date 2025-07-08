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

