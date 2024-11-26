---
title: A Fool's Grimoire
subtitle: some computer user attempts things
author: Seb
author-url: /
date: 2024-11-25
lang: en
toc-title: Contents
version: v1.0.0
---

### Explorations

This section links to explorations made into various topics.

#### Performance Engineering Starter Pack

This series of posts goes through a small breadth-first foray into software
performance measurement tooling and techniques. It also investigates some
parallelisation techniques, such as GPU programming.

The main goal of this series was to become more familiar with various performance
related technologies and techniques.

[Read here](/posts/perf/perf-engineering-intro/introduction.html)

<hr>

### References

This section contains collections of resources for various topics.
Surely it will be expanded over time.

- [Litanies of Performance](/posts/references/litanies-of-performance.html)

<hr>

### Archive

This section holds older posts/goings on from a few years ago. Some have their
own pages, others are just a small description here.

#### picoCTF 2019

[Beginner binary exploitation writeup of a few challenges](/posts/archive/picoctf2019/2019-10-29-picoctf2019.html), done as part of picoCTF.

#### FILE Exploitation 2020

[A small dive into glibc FILE exploitation](/posts/archive/angstrom-file2020/2020-04-29-file_exploitation.html).

#### tghack 2020

[A CTF writeup from tghack 2020](/posts/archive/tghack2020/2020-05-01-tghack2020.html).

#### DownUnderCTF 2020 Browser Exploitation

[This is a writeup of a Chrome v8 exploitation challenge from DownUnderCTF](/posts/archive/ductf2020/2020-09-28-ductf2020-pwn-or-web.html).

#### Rootkit Larning Exercise

[Code for a rootkit made as a learning exercise](https://github.com/seb-sec/trivial-rootkit)
early on in my security learning adventure as part of a University course.

#### Black Box Fuzzer

[Code for a black box fuzzer](https://github.com/Josh-Murray/fuzzer/tree/dev) made
in a team as part of a University project. I worked on the harness component of
this fuzzer, which managed the binary that was being tested (setting it up,
feeding it inputs, managing crashes). Some additional features I worked on
include a simple code coverage mechanism using `ptrace()` and a memory snapshot
mechanism to improve fuzzer performance.

#### Open Source Bug Finding

When looking at the [Janet programming language](http://www.github.com/janet-lang/janet),
I discovered a few memory corruption bugs in the project (issues 
[#416](http://www.github.com/janet-lang/janet/issues/416),
[#409](http://www.com/janet-lang/janet/issues/409),
[#407](http://www.github.com/janet-lang/janet/issues/407)) by fuzz testing, and
further dynamic analysis using `gdb` to pinpoint the cause of the bugs.

<hr>

### Site Theme

The theme was adapted from [Oskar Wickström's design](https://owickstrom.github.io/the-monospace-web/), with code at [github.com/owickstrom/the-monospace-web](https://github.com/owickstrom/the-monospace-web).

