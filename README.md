## Introduction ##

A set of problems based around learning the basics of smashing the stack in a modern context.

REQUIREMENTS: Ability to compile both 32 bit and 64 bit binaries.

Problem sets are roughly ordered by difficulty, however later problems in an earlier set may be harder than earlier problems in a later set.

You can build a particular problem using `make <set>_level<number>` where the set is the name of the problem set and the number is the problem in the set.

Current Problem Sets:
- stack     : Introduction to manipulating memory on the stack
- shellcode : Try to get some shellcode running
- fstring   : An intro to format string vulnerabilities
- rlibc     : Try to return to libc
- got       : Hammer the global offset table
- rop       : Build gadgets for great victory

More problems may be added to these sets

Future Problem Sets:
These haven't been written yet, but are aspired to.
- heap      : A range of problems focusing on heap exploitation (houses of prime, mind etc)
- strcpy    : Vulnerable strcpy rather than raw scanf/fgets
- x64       : Porting to 64 bit
- canary_ev : Problems focusing on avoiding the canary
- aslr_ev   : Problems focusing on bypassing ASLR
- dtors     : .DTORS as a target
- atexit    : Atexit as a target
- int_hand  : Interrupt handler as a target


Feel free to write your own problems and submit a PR.

## Problem Approach ##
It's suggested that as you solve each problem you write a script to automate its execution.

## Resources ##
If you're stuck on a particular problem you may find the following resources useful.

### stack ###
- K&R C
- The gdb manual
- Compilers: Principles, Techniques and Tools

### shellcode ###
- Smashing the Stack for Fun and Profit
- Shellcoder's Handbook

### fstring ###
- Exploiting Format String Vulnerabilities, scut / teso

### rlibc ###
- Bypassing non-executable-stack during exploitation using return-to-libc, c0ntex
- Phrack 58 0x04, nergal

### got ###
- How to hijack the Global Offset Table with pointers for root shells, c0ntex

### rop ###
- Return-oriented Programming:Exploitation without Code Injection, Buchanan,Roemer, Savage, Shacham

## Solutions ##
Write your own, you'll learn a grand total of jack squat from this if you use automated tools or use someone else's solutions. 
