---
layout: project
author: "seb-sec"
title: "pwn-playground"
excerpt_separator: <!--more-->
tags: [project, binary exploitation]
---

Small environment to practice exploitation techniques without many restrictions

<!--more-->

[pwn-playground github](https://github.com/seb-sec/pwn_playground)

This project has several features to assist in performing different types of exploitation (targeted at basic C programs, but the concepts apply elsewhere too).

Also included is a set of python functions using pwntools to assist in interacting with the program, so the user can focus on exploitation.

Users can adjust the Makefile to change the program protections or target architecture, some basic options are provided as comments.

Users may also want to change what version of libc they are linking. Some suggestions are provided on the github page.

The main idea is to allow the user to practice exploitation techniques in a fast way under whatever self-imposed scenario they want. For example: under libc 2.30, given a single arbitrary write + a libc leak and all protections enabled, can I still pop a shell from a basic buffer overflow? (yes)

These scenarios may be artificial, but they should still (hopefully) help in increasing someones understanding of how programs work internally and how to exploit them.

<br>

<hr>

## Features

Below is an overview of the included features and some helpful resources.

### Buffer overflow module

Simple function that calls `gets()` on a small buffer.

Some helpful resources:

* [Smashing the stack for fun and profit](http://phrack.org/issues/49/14.html)
* The Shellcoder's Handbook: Discovering and Exploiting Security Holes by Chris Anley and friends

<br>

### Format string module

Another simple function, will call `printf()` on user supplied input.

For resources, try the Shellcoders Handbook mentioned above

<br>

### Heap module

A collection of functions to allocate, write to, read from and free heap chunks.

For resources, first understand the inner workings of the dynamic memory allocator you are targetting (for the program, its [glibc's malloc](https://sourceware.org/glibc/wiki/MallocInternals)). Then read up on some basic exploitation strategies (some more resources are linked in [this](https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/) article)

Change the version of libc you are linking against to explore how heap protection mechanisms have changed over time

<br>

### FILE module

A collection of functions that perform different FILE operations on a pointer to a FILE struct. Also included is a function to corrupt this struct, which can lead to some interesting exploits.


I recommend looking at [Angel Boy's slides](https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique) for some ideas, as well as [Dhaval Kapil's article](https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/)

<br>

### Other functionality

Also included are other functions that may be useful:

* Leak segment address
  * Prints an address from a segment of choice in the program (text, heap, libc or stack)
* Arbitrary read
  * Read a value from an arbitrary address
* Arbitrary write
  * Write a value of choice to an arbitrary address
* Fork server
  * Performs a `fork()` and sends child to the main program loop while the parnts waits. If the child crashes the parent will re-fork and wait again.
  * Mainly designed for practicing [BROP](http://www.scs.stanford.edu/~sorbo/brop/bittau-brop.pdf) locally, but there could be other fun usage scenarios

