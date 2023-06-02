# crackme solution

This is a walk-through solving a crackme written by reddit user [u/CaptainMeatloaf](https://www.reddit.com/user/CaptainMeatloaf/).

The original post is available [here](https://www.reddit.com/r/ReverseEngineering/comments/13xhkfg/another_small_re_challenge/), which includes some comments about getting the crackme up and running in a Raspberry Pi emulator, with the actual crackme and instructions hosted [here](https://hunter2.watchingyour.tv/crackme.html).

# here we go
Once we get everything set up, we can try random words:
```
pi@raspberrypi:~$ ./crackme banana
You didn't enter the correct key :(
```
We know what we don't want at least.

I should point out right now that I knew next to nothing about using gdb to debug going into this, or how half the ARM instruction set works, which isn't to make this challenge sound trivial (it was not,) it just goes to show that general concepts learned with one language or tool carry over really well to others, though trying completely unfamiliar challenges is a great way to branch out.

I mention all of this primarily because my workflow is probably going to seem a bit chaotic.  I opened the crackme up in IDA and Ghidra and used those for most of the work, while fumbling my way around gdb to figure out what I needed to be looking for in those.

Quick string search in IDA.  Don't see our failure text, or anything that looks like success or our password.  There's a "0123456789"  which looks promising until we remember that's not an English word (though we of course try it anyway.)

Hopefully the failure text is just output with printf or puts using a string that's built or decrypted.  It could be output a char at a time by some convoluted means, or using fprint* functions to write to stdout, but we'll deal with that later if we have to.

Let's break on printf and run it with some random password argument:
```
pi@raspberrypi:~$ gdb crackme
...
(gdb) info functions printf*
All functions matching regular expression "printf*":

Non-debugging symbols:
0x00010c50  printf@plt
0x00010e54  sprintf@plt
(gdb) break printf@plt
Breakpoint 1 at 0x10c50
(gdb) run AAAAAA
Starting program: /home/pi/crackme AAAAAA
...
Breakpoint 1, 0x00010c50 in printf@plt ()
(gdb) x /s $r0
0x7efffb34:	"Debugger detected, exiting\n"
```
So I was wrong before.  NOW we know what we don't want.

In Windows, the simplest kind of debugger check is checking the BeingDebugged flag in the PEB.  The linux equivalent is opening /proc/self/status and searching for "TracePID:" which would have information about which process is debugging the current one, or won't be present at all if it isn't being debugged.

We can trace our way back up the stack like so:
```
(gdb) info frame
Stack level 0, frame at 0x7efffb30:
 pc = 0x10c50 in printf@plt; saved pc = 0x114fc
 called by frame at 0x7efffb58
 Arglist at 0x7efffb30, args: 
 Locals at 0x7efffb30, Previous frame's sp is 0x7efffb30
```
Where "saved pc" is our return address.  If we navigate to 0x114fc in IDA we see:
```
.text:000114F8                 BL      printf
.text:000114FC                 BL      getpid
```
An instruction right after a call to printf, so we know our virtual addresses in IDA at least match up with our debugging session.

If we scroll up in IDA and poke around, we see a call at the beginning to sub_112A8, which is very clearly opening /proc/self/status and searching for "TracePID:", so that's at least one debugger check.  There could be more, but let's try sinking this one first.
The easiest thing I thought of was just overwriting "TracePID:" with some garbage it won't find.  Maybe some other dynamic/obfuscated code also references these strings to do the same search elsewhere so that we accidentally help ourselves out more than we think, but it's mostly just simpler than figuring out which instructions to patch to make it fail some more clever way.

IDA has "TracePID:" at address 0x28C08 so hopefully it's the same during debugging.  We kill gdb and reopen it then try out our theory:
```
pi@raspberrypi:~$ gdb crackme
...
(gdb) starti AAAAAA
Starting program: /home/pi/crackme AAAAAA

Program stopped.
0x76fcea30 in _start () from /lib/ld-linux-armhf.so.3
(gdb) x /s 0x28C08
0x28c08:	"TracerPid:"
(gdb) set *0x28c08 = 0x41414141
(gdb) x /s 0x28C08
0x28c08:	"AAAAerPid:"
(gdb) c
Continuing.
...
You didn't enter the correct key :(
```
Who knew we'd be so happy to see that a few minutes ago?  We have to use starti to start it up and break on the first instruction before we can do anything with its memory.  That's probably obvious, but most debuggers I'm used to do that already when you load a process so it had me scratching my head for a bit.

It seems like the search string is where we hoped to find it, and screwing it up successfully bypasses the debugger check.  There are cleaner ways to overwrite a char string in memory, but I struggled figuring out the syntax for them so I went with what worked and moved on.

Opening a new session and putting what we did in the last two together, we can bypass the debugger check and break on printf, get the saved pc to see where the failure message is called from, and find that we return to 0x11624:

![Screenshot of return after failure message printf in IDA](https://raw.githubusercontent.com/charlesnathansmith/crackme/main/ida1.png)

That BNE instruction looks fairly important.  The data at unk_3C500 and unk_3C50C look like garbage, but the branch is deciding which of them to feed into sub_11218 right before our error message gets printed, so maybe it's the encrypted version of the message to display.

Let's change what it does and see if we can get to the success message.  This isn't our end goal, since we want the password that will naturally get us there, but it's a start to backtracing its decision-making process.  We'll actually back up to the CMP right before it:
```
pi@raspberrypi:~$ gdb crackme
(gdb) starti AAAAA
(gdb) set *0x28c08 = 0x41414141
(gdb) break *0x115F8
Breakpoint 1 at 0x115f8
(gdb) c
...
Thread 1 "crackme" hit Breakpoint 1, 0x000115f8 in ?? ()
(gdb) x /2i $pc
=> 0x115f8:	cmp	r3, #0
   0x115fc:	bne	0x1160c
```
Looks like we're in the right place
```
(gdb) print $r3
$1 = 1
```
We know the password is wrong.  So if this is our password test branch, then $r3 should be 0 at this comparison to get the correct result
```
(gdb) set $r3 = 0
(gdb) c
Continuing.
Success!
```
There we go!  If we were just looking to patch it, we'd pretty much be done here, but alas life is not so simple.

Since the only difference between branches is the byte pointer being fed to sub_11218 via r3, either a decryption or some kind of further checks has to happen in there.

Since as stated before I am functionally illiterate when it comes to ARM, we cheat a bit here and see if we can coax something sensible out of Ghidra's decompiler:

![Screenshot showing Ghidra's decompilation of sub_11218](https://raw.githubusercontent.com/charlesnathansmith/crackme/main/ghidra1.png)

Can't ask for better than that.  That is without doubt the cleanest code I've ever gotten Ghidra to produce.  It's a rolling XOR decryption that XORs the first byte with 0xff, the next byte with 0xfe, and so on decrementing the value it's XORed by until an entire string is decoded.

Since we know what the result messages are, this wouldn't really be worth exploring any more, but if we look up in our main sub_1153C function before the CMP happens, we can see it used a couple more times on some other inputs.  So maybe it spits out the password in cleartext or something.  That doesn't quite make sense given the way it's structured, but I want to know what else they are doing.

Here's a cleaned up implementation that tests it using the encrypted output messages from the program to make sure it's working:

[dec1.cpp](https://github.com/charlesnathansmith/crackme/blob/main/dec1.cpp)

Those outputs look correct, including the garbage chars printed after the failure notice.

Now we can restart gdb, patch the debugging check (I'm sure that part is scriptable but it's only one line here,) set a breakpoint on sub_11218 ("break *0x11218"), then each time it's hit, we can print the bytes pointed to by r3, feed them into our decryption function, and see if we get anything intelligible.

I'll save you a lot of trouble here and let you know the decrypted results from the earlier calls aren't in any language I speak.

Let's see if Ghidra can chew on our main function and spit out anything sensible, so we can get a better sense about what's being decrypted:

![Screenshot of Ghidra's decompilation of the main function](https://raw.githubusercontent.com/charlesnathansmith/crackme/main/ghidra2.png)

That's... better?

The highlighted comparison ("local_18 == 0") is our BNE we were playing with earlier that selects the output message.  We want to know where local_18 comes from.

It's set with this line:
```
local_18 = (*(code *)((int)local_14 + local_10 + -0x84))(*(undefined4 *)(param_2 + 4));
```
Which as messy as it looks, really just calculates a function pointer, calls that pointer with some argument, and then sets local_18 to the return value.

local_10 is defined as 0xa4, so the address of the function being called is (local_14 + 0xa4 - 0x84) = (local_14 + 0x20)

To make a long story short, mmap() is similar to VirtualAlloc in Windows, and allocates memory with certain permissions.  local_14 stores the pointer to this memory, and 0x2e0 bytes are copied into it from DAT_0003c1fc.  local_14 is then used as the argument to our decryption sub_11218 (Ah-hah!), so those bytes get decrypted, then a call is made to local_14+0x20, and the return value determines which message to give.

Let's copy 0x2e0 bytes starting at DAT_0003c1fc (0x3c1fc) over to our decryptor and see what it gives us:

[dec2.cpp](https://github.com/charlesnathansmith/crackme/blob/main/dec2.cpp)

It probably would've been more sensible just to have it write the output on out to a file, but I was still checking some things with it at the time and just copy/pasted the output into a hex editor to save as a binary.

We open this binary up in Ghidra, setting the language to the same settings as it found for crackme (ARM v8 32-bit LE) and load it without analyzing.  We know the code gets called into at offset 0x20, so we find that location, tell it to start disassembly there, and low and behold:

![Screenshot of Ghidra's decompilation of the decrypted function](https://raw.githubusercontent.com/charlesnathansmith/crackme/main/ghidra3.png)

Nothing left to do but try it:

![Screenshot of the discovered password being correctly entered](https://raw.githubusercontent.com/charlesnathansmith/crackme/main/success.png)

Yay.
