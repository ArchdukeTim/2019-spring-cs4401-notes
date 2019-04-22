---
title:  "Writeup: heap0"
date:   2019-04-13 5:00:00
categories: writeup
layout: post
author: Kyle Savell
---

In stack0, we were tasked with overflowing a buffer to manipulate a local variable on the stack. Similarly, in heap0 we are tasked with overflowing a buffer to manipulate data, but this time in dynamically allocated data in the heap. Here is the source code we are given to work with:


```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
                                                                                                                           
struct data {
  char name[64];
};                                                                                                                         
                                                                                                                           
struct fp {
  int (*fp)();
};                                                                                                                         
                                                                                                                           
void winner()
{                                                                                                                          
  char buffer[64];
  FILE *fp;
                                                                                                                           
  printf("Level passed\n");
                                                                                                                           
  fp = fopen("./flag.txt", "r");
                                                                                                                           
  fgets(buffer, 64, (FILE*)fp);
  printf("flag: %s\n", buffer);
}                                                                                                                          
                                                                                                                           
void nowinner()
{                                                                                                                          
  printf("level has not been passed\n");
}
                                                                                                                           
int main(int argc, char **argv)
{
  struct data *d;
  struct fp *f;
                                                                                                                           
  d = malloc(sizeof(struct data));
  f = malloc(sizeof(struct fp));
  f->fp = nowinner;                                                                                                        
                                                                                                                           
  printf("data is at %p, fp is at %p\n", d, f);
                                                                                                                           
  strcpy(d->name, argv[1]);
                                                                                                                           
  f->fp();                                                                                                                 
}
```

This challenge contains a sizable source code, so let's break it down piece by piece.

```c
struct data {
  char name[64];
}; 
```

The first piece of code is `data`, which is a `struct`. Structs are only put in memory when memory is explicitly allocated for them using a command such as `malloc`, so whenever a new `data` struct is `malloc`'ed in the source code it will be put onto the heap. The only structure inside `data` is a 64-byte buffer (we'll need this later).

```c
struct fp {
  int (*fp)();
};  
```

The next bit of code is also a struct, `fp`. The syntax `int (*fp)();` is a structure that is referring to a function pointer - it will hold the address of a function so that it can be called from the struct.

```c
void winner()
{                                                                                                                          
  char buffer[64];
  FILE *fp;
                                                                                                                           
  printf("Level passed\n");
                                                                                                                           
  fp = fopen("./flag.txt", "r");
                                                                                                                           
  fgets(buffer, 64, (FILE*)fp);
  printf("flag: %s\n", buffer);
} 
```

`winner` is the function that needs to be called in order to complete the challenge. There is no hoops to jump through inside of the function itself, we just need to be able to access it.

```c
void nowinner()
{                                                                                                                          
  printf("level has not been passed\n");
}
```

`nowinner` is the function that will be called when the binary is not exploited correctly.

```c
int main(int argc, char **argv)
{
  struct data *d;
  struct fp *f;
                                                                                                                           
  d = malloc(sizeof(struct data));
  f = malloc(sizeof(struct fp));
  f->fp = nowinner;                                                                                                        
                                                                                                                           
  printf("data is at %p, fp is at %p\n", d, f);
                                                                                                                           
  strcpy(d->name, argv[1]);
                                                                                                                           
  f->fp();                                                                                                                 
}
```

The `main` function encapsulates all of the above snippets of code. At the beginning of `main` a `data` struct and a `fp` struct are created, so both structs are placed on the heap (note that the `data` struct is `malloc`'ed first). In the line directly below the memory allocations for the structs, the function pointer that is inside the created `fp` struct is set to the `nowinner` function. Below this is a `printf` line, which we will come back to in a minute. Next, `strcpy` is used to copy the first argument of `heap0` into the 64-byte buffer in the created `data` struct. Lastly, `f->fp();` will call the function that is stored inside the `fp` struct, which was set to `nowinner` before, so by default `nowinner` will be called and then the program will terminate.

Let's run the program to see what happens. When you do, you will see a print statement show up and then the program will end.

```
data is at 0x804b008, fp is at 0x804b050
```

This is the `printf` that we skipped over before. If we dig into the line of code, we see two `%p` specifiers, which print out pointers. In particular, this print statement is printing out the addresses of the `data` and `fp` structs on the heap.

Using our knowledge from stack0 and how this binary is set up, we can start to formulate a plan of attack. At the end of `main`, we know that the `nowinner` function is being called and then the program ends. What we want is the `winner` function to be called instead, meaning that we want the function pointer inside of `fp` to be pointing to the function address of `winner`.

In order to accomplish this, a buffer overflow can be used. We want to overwrite the address that is stored in `fp`, but how do we do this? If you recall, there is a 64-byte buffer stored in the `data` struct. This buffer is filled with input from the first heap0 function argument using `strcpy`. If we use `man strcpy` to look at what this function does, we see that it copies a string from a source to a destination buffer, but it does not appear to limit the length of the source. Judging by the helpful line `Beware of buffer overruns!` we can assume that we can indeed use this function to cause a buffer overflow.

How will we know what the payload will be? We know that we want to overwrite the function pointer in `fp` with the address of `winner`, but what is that address and how do we put it in the correct memory location? First, let's find the address of `winner`. We can use the handy command `objdump -d` to show a complete disassembly of heap0. Alternatively, in gdb `disas winner` will show just the disassembly of the `winner` function.

```
0804851b <winner>:                                                                                                         
 804851b:       55                      push   %ebp                                                                        
 804851c:       89 e5                   mov    %esp,%ebp                                                                   
 804851e:       83 ec 58                sub    $0x58,%esp                                                                  
 8048521:       83 ec 0c                sub    $0xc,%esp                                                                   
```

From the disassembly we can see the address in memory where the `winner` function starts. This is the address we are looking to use! To figure out where we need to put the address, let's take another look at the printout.

```
data is at 0x804b008, fp is at 0x804b050
```

If we look at the address for `data`, we see that the address is smaller than the address of `fp`. In the heap addresses "grow" upwards, so becase `data` was conveniently `malloc`'ed before `fp`, the buffer is in a location where overflowing it can cause `fp` to be overwritten. It is important to clarify that the address of `data` is the address of the beginning of the buffer, and the address of `fp` is the address that `nowinner` is being stored at. This means that regardless of the buffer size, the byte padding to put before the address of `winner` in our exploit string will be `0x804b050 - 0x804b008`.

Pulling all of this together, we will have an exploit string that will look like:

```
./heap0 "`python -c 'print (padding) + (winner address)'`"
```
