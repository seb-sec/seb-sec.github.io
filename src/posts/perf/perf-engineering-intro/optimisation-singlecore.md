---
title: Single Core Optimisations
author: Seb
author-url: /
date: 2024-11-25
lang: en
toc-title: Contents
version: v1.0.0
---

### Optimisations

This section begins looking at various things that can be done to improve the
performance of the sample code. Like the measurement section, this is more of a
journey of exploration into various techniques, and will serve to inform a
future reference page that tracks various techniques.

Some of the techniques explored include various algorithmic modifications,
such as rewriting hot loops, using small angle trigonometric approximations,
and using Taylor series approximations. Others techniques include attempting to
optimise branch prediction, examining the sort of optimisations made by compiler
flags, and using vector instrinsics.

The same code is used from the previous section for the most part (although
different code examples might be explored along the way):

```C
    double a = 0;
    double b = M_PI/4;
    double split = 1000000000;

    double ans_riemann = integral_riemann(f_simple, b, a, split);
    double ans_analytical = integral_analytical(antiderivative_f_simple, b, a);
```

The `split` variable is set to 1 billion by default, resulting in
a Riemann sum taken with 1 billion rectangles. Both the `f_simple`
and `f_intermediate` functions are tested.

The base case was compiled with:

```
gcc main.c -o main.out -lm
```

The compiler version is gcc version 14.2.1 20240912 (Red Hat 14.2.1-3).

The CPU used is a AMD Ryzen 7 7840U.

### Tools

The main tools that will be used to measure performance are `perf` and `bptrace`.

`perf record` will be used to get an idea of where the code spends the most time
(and how this value changes across tests).

```
$ perf record -F 50000 ./main.out
$ perf report --percent-limit 1
```

`perf stat` will be used to examine various performance related statistics,
including instructions executed, cycles taken, and some branch/cache statistics.

```
$ perf stat -d -r 5 ./main.out
```

`bpftrace` will be used to measure the runtime of the main function of interest,
`integral_riemann` using the following script:

```
uprobe:./main.out:integral_riemann {
    @start[tid] = nsecs;
}

uretprobe:./main.out:integral_riemann
/@start[tid]/
{
    // Microsecond time difference
    printf("Microseconds in Riemann integral: %lld\n", (nsecs - @start[tid]) / 1e3);
    delete(@start[tid]);
}

END {
    clear(@start);
}
```

```
$ sudo bpftrace trace.bt -c main.out
```

Note that for convenience during testing two different 'main' programs were
compiled for the simple and intermediate cases, so the output may contain
references to filenames in the form `simple-main.out` and `intermediate-main.out`.

<hr>

### Base Case

This is the base case with no modifications made. All other results will be
be compared to this case to calculate their performance improvements.

#### Measurement - Simple

`perf stat`:

```
 Performance counter stats for './simple-main.out' (5 runs):

          6,790.06 msec task-clock                       #    1.000 CPUs utilized               ( +-  0.32% )
                19      context-switches                 #    2.798 /sec                        ( +- 21.87% )
                 0      cpu-migrations                   #    0.000 /sec                 
                74      page-faults                      #   10.898 /sec                        ( +-  0.33% )
    32,860,040,463      cycles                           #    4.839 GHz                         ( +-  0.05% )  (71.42%)
        65,087,926      stalled-cycles-frontend          #    0.20% frontend cycles idle        ( +-  0.66% )  (71.42%)
    94,076,906,095      instructions                     #    2.86  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.02% )  (71.42%)
    11,016,541,268      branches                         #    1.622 G/sec                       ( +-  0.02% )  (71.42%)
         1,787,269      branch-misses                    #    0.02% of all branches             ( +-  0.30% )  (71.43%)
    31,023,595,059      L1-dcache-loads                  #    4.569 G/sec                       ( +-  0.01% )  (71.44%)
           698,810      L1-dcache-load-misses            #    0.00% of all L1-dcache accesses   ( +-  2.32% )  (71.43%)
   <not supported>      LLC-loads                                                        
   <not supported>      LLC-load-misses                                                  

            6.7914 +- 0.0214 seconds time elapsed  ( +-  0.32% )
```

`perf record`:

```
Samples: 364K of event 'cycles:P', Event count (approx.): 33305610924
Overhead  Command   Shared Object           Symbol
  79.44%  simple-main.out  libm.so.6        [.] __cos_fma
  11.65%  simple-main.out  simple-main.out  [.] integral_riemann
   7.66%  simple-main.out  simple-main.out  [.] f_simple
   1.01%  simple-main.out  simple-main.out  [.] cos@plt
```

`bpftrace`:

```
Microseconds in Riemann integral: 6847828
```

#### Measurement - Intermediate

`perf stat`:

```
 Performance counter stats for '../intermediate-main.out' (5 runs):

         14,740.38 msec task-clock                       #    1.000 CPUs utilized               ( +-  0.10% )
               157      context-switches                 #   10.651 /sec                        ( +- 74.36% )
                 1      cpu-migrations                   #    0.068 /sec                        ( +- 58.31% )
                69      page-faults                      #    4.681 /sec                        ( +-  0.46% )
    70,807,868,902      cycles                           #    4.804 GHz                         ( +-  0.10% )  (71.43%)
       144,735,511      stalled-cycles-frontend          #    0.20% frontend cycles idle        ( +-  1.62% )  (71.43%)
   235,111,065,770      instructions                     #    3.32  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.01% )  (71.43%)
    24,031,121,304      branches                         #    1.630 G/sec                       ( +-  0.01% )  (71.43%)
         3,867,468      branch-misses                    #    0.02% of all branches             ( +-  0.65% )  (71.43%)
    65,087,953,018      L1-dcache-loads                  #    4.416 G/sec                       ( +-  0.02% )  (71.43%)
         1,848,541      L1-dcache-load-misses            #    0.00% of all L1-dcache accesses   ( +-  7.65% )  (71.43%)
   <not supported>      LLC-loads                                                        
   <not supported>      LLC-load-misses                                                  

           14.7420 +- 0.0146 seconds time elapsed  ( +-  0.10% )
```

`perf record`:

```
Samples: 769K of event 'cycles:Pu', Event count (approx.): 71618312319
Overhead  Command          Shared Object          Symbol
  60.73%  intermediate-ma  libm.so.6              [.] __ieee754_pow_fma
  24.35%  intermediate-ma  libm.so.6              [.] __cos_fma
  10.91%  intermediate-ma  libm.so.6              [.] pow@@GLIBC_2.29
   2.67%  intermediate-ma  intermediate-main.out  [.] f_intermediate
   1.27%  intermediate-ma  intermediate-main.out  [.] integral_riemann
```

`bpftrace`:

```
Microseconds in Riemann integral: 14846748
```

<hr>

### Compiler Flags

The first thing to try is getting the compiler to do some optimisations for us
by compiling with `-03`.

The instructions of the functions of interest were compared using `objdump`.
Some of the changes seen include:

- The `rbp` register was not used as the base pointer
- The original code tended to use local stack variables (referenced via offsetting from the base pointer `rbp`) more often, and tended to use a smaller set of registers. For example, in the disassembly for the `integral_riemann` function without additional optimisations, an instruction snippet looks like:

```
  40127b:	48 89 7d d8          	mov    QWORD PTR [rbp-0x28],rdi
  40127f:	f2 0f 11 45 d0       	movsd  QWORD PTR [rbp-0x30],xmm0
  401284:	f2 0f 11 4d c8       	movsd  QWORD PTR [rbp-0x38],xmm1
  401289:	f2 0f 11 55 c0       	movsd  QWORD PTR [rbp-0x40],xmm2
  40128e:	66 0f ef c0          	pxor   xmm0,xmm0
  401292:	f2 0f 11 45 f8       	movsd  QWORD PTR [rbp-0x8],xmm0
  401297:	f2 0f 10 45 d0       	movsd  xmm0,QWORD PTR [rbp-0x30]
  40129c:	f2 0f 5c 45 c8       	subsd  xmm0,QWORD PTR [rbp-0x38]
  4012a1:	f2 0f 5e 45 c0       	divsd  xmm0,QWORD PTR [rbp-0x40]
  4012a6:	f2 0f 11 45 e8       	movsd  QWORD PTR [rbp-0x18],xmm0
  4012ab:	f2 0f 10 45 c8       	movsd  xmm0,QWORD PTR [rbp-0x38]
  4012b0:	f2 0f 11 45 f0       	movsd  QWORD PTR [rbp-0x10],xmm0

```

- In the optimised code, fewer references using memory offsets were seen, instead the compiler preferred to use a larger set of registers. In the same function, an instruction snipper looks like:

```
  401290:	f2 0f 5e c2          	divsd  xmm0,xmm2
  401294:	66 0f ef d2          	pxor   xmm2,xmm2
  401298:	48 83 ec 28          	sub    rsp,0x28
  40129c:	66 0f 2f e9          	comisd xmm5,xmm1
  4012a0:	f2 0f 11 44 24 18    	movsd  QWORD PTR [rsp+0x18],xmm0
  4012a6:	76 43                	jbe    4012eb <integral_riemann+0x6b>
  4012a8:	48 89 fb             	mov    rbx,rdi
  4012ab:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
  4012b0:	f2 0f 11 54 24 10    	movsd  QWORD PTR [rsp+0x10],xmm2
  4012b6:	66 0f 28 c1          	movapd xmm0,xmm1
  4012ba:	f2 0f 11 4c 24 08    	movsd  QWORD PTR [rsp+0x8],xmm1
  4012c0:	ff d3                	call   rbx
  4012c2:	f2 0f 10 5c 24 18    	movsd  xmm3,QWORD PTR [rsp+0x18]
  4012c8:	f2 0f 10 4c 24 08    	movsd  xmm1,QWORD PTR [rsp+0x8]
  4012ce:	66 49 0f 6e e6       	movq   xmm4,r14
  4012d3:	f2 0f 10 54 24 10    	movsd  xmm2,QWORD PTR [rsp+0x10]
  4012d9:	f2 0f 58 cb          	addsd  xmm1,xmm3
  4012dd:	f2 0f 59 c3          	mulsd  xmm0,xmm3
  4012e1:	66 0f 2f e1          	comisd xmm4,xmm1
  4012e5:	f2 0f 58 d0          	addsd  xmm2,xmm0
```

- Also seen above, the compiler added multi-byte `nop` instructions, probably for memory alignment purposes
- Where possible it has eliminated unnecessary instructions. Comparing the unoptimised `f_simple` disassembly with the optimised one highlights this (also note the 11 bytes added in the form of a nop and some `0x00` bytes to ensure 16-byte alignment):

```
# Base case
0000000000401146 <f_simple>:
  401146:	55                   	push   rbp
  401147:	48 89 e5             	mov    rbp,rsp
  40114a:	48 83 ec 10          	sub    rsp,0x10
  40114e:	f2 0f 11 45 f8       	movsd  QWORD PTR [rbp-0x8],xmm0
  401153:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  401157:	66 48 0f 6e c0       	movq   xmm0,rax
  40115c:	e8 df fe ff ff       	call   401040 <cos@plt>
  401161:	c9                   	leave
  401162:	c3                   	ret
```

```
# -O3 case
0000000000401190 <f_simple>:
  401190:	e9 bb fe ff ff       	jmp    401050 <cos@plt>
  401195:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  40119c:	00 00 00 00
```

- The `main` function doesn't even call the `integral_riemann`/`integral_analytical` functions- these have been inlined. Unfortunately this causes the measurement tools to not work properly, so the `__attribute__ ((noinline))` attribute was added to those functions. This hopefully shouldn't affect the final output too much

Other compiler flags such as `-ffast-math` can also be used. In this case, the calls to `pow()` are replaced with calls to `exp()` (which really is the function that
should have been used in the first place, however it was left out to explore
potential optimisations). This caused some surprisingly
large changes in execution speed (in the intermediate case only).

The `gcc` manual specifies that the `-ffast-math` flag can result in incorrect
output for programs that depend on an exact implementation of the IEEE
specification.
This may make it unsuitable for some applications, but in others this may be
tolerable (in the tested code this did not make a difference in the accuracy
of the output).

<br>

#### gcc -O3

Code compiled with just the `-O3` flag.

##### Measurement - Simple


`perf stat`:

```
 Performance counter stats for './simple-main-O3.out' (5 runs):

          6,425.94 msec task-clock                       #    1.000 CPUs utilized               ( +-  0.55% )
                17      context-switches                 #    2.646 /sec                        ( +- 10.94% )
                 0      cpu-migrations                   #    0.000 /sec                 
                75      page-faults                      #   11.671 /sec                        ( +-  0.78% )
    31,560,271,362      cycles                           #    4.911 GHz                         ( +-  0.01% )  (71.42%)
        65,815,320      stalled-cycles-frontend          #    0.21% frontend cycles idle        ( +-  1.30% )  (71.42%)
    83,095,613,744      instructions                     #    2.63  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.01% )  (71.43%)
    10,019,031,111      branches                         #    1.559 G/sec                       ( +-  0.02% )  (71.43%)
         1,676,332      branch-misses                    #    0.02% of all branches             ( +-  0.57% )  (71.45%)
    25,022,073,585      L1-dcache-loads                  #    3.894 G/sec                       ( +-  0.01% )  (71.43%)
           610,135      L1-dcache-load-misses            #    0.00% of all L1-dcache accesses   ( +-  8.25% )  (71.41%)
   <not supported>      LLC-loads                                                        
   <not supported>      LLC-load-misses                                                  

            6.4273 +- 0.0355 seconds time elapsed  ( +-  0.55% )
```

`perf record`:

```
Samples: 350K of event 'cycles:P', Event count (approx.): 31907563444
Overhead  Command          Shared Object            Symbol
  89.13%  simple-main-O3.  libm.so.6                [.] __cos_fma
   8.99%  simple-main-O3.  simple-main-O3.out       [.] integral_riemann
   1.07%  simple-main-O3.  simple-main-O3.out       [.] cos@plt
```

`bpftrace` (averaged over a few runs)

```
Microseconds in Riemann integral: 6454392
```

##### Measurement - Intermediate

`perf stat`:

```
 Performance counter stats for './intermediate-main-O3.out' (5 runs):

         13,748.10 msec task-clock                       #    1.000 CPUs utilized               ( +-  0.42% )
                35      context-switches                 #    2.546 /sec                        ( +-  6.54% )
                 1      cpu-migrations                   #    0.073 /sec                        ( +- 44.72% )
                75      page-faults                      #    5.455 /sec                        ( +-  0.78% )
    66,232,794,035      cycles                           #    4.818 GHz                         ( +-  0.02% )  (71.42%)
       140,936,105      stalled-cycles-frontend          #    0.21% frontend cycles idle        ( +-  0.86% )  (71.42%)
   228,149,636,174      instructions                     #    3.44  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.02% )  (71.42%)
    24,032,736,261      branches                         #    1.748 G/sec                       ( +-  0.02% )  (71.42%)
         3,584,963      branch-misses                    #    0.01% of all branches             ( +-  0.65% )  (71.43%)
    61,050,291,939      L1-dcache-loads                  #    4.441 G/sec                       ( +-  0.01% )  (71.44%)
         1,270,363      L1-dcache-load-misses            #    0.00% of all L1-dcache accesses   ( +-  2.59% )  (71.43%)
   <not supported>      LLC-loads                                                        
   <not supported>      LLC-load-misses                                                  

           13.7493 +- 0.0578 seconds time elapsed  ( +-  0.42% )
```

`perf report`

```
Samples: 737K of event 'cycles:P', Event count (approx.): 66984803585
Overhead  Command          Shared Object             Symbol
  33.81%  intermediate-ma  libm.so.6                 [.] __ieee754_pow_fma
  19.89%  intermediate-ma  libm.so.6                 [.] __cos_fma
  17.10%  intermediate-ma  libm.so.6                 [.] pow@@GLIBC_2.29
  15.10%  intermediate-ma  libm.so.6                 [.] __pow_finite@GLIBC_2.15@plt
   7.26%  intermediate-ma  intermediate-main-O3.out  [.] integral_riemann
   5.52%  intermediate-ma  intermediate-main-O3.out  [.] f_intermediate
```


`bpftrace`:

```
Microseconds in Riemann integral: 13707645
```

<br>

#### gcc -O3 -ffast-math

Code compiled with `-O3 -ffast-math` which causes the replacement of the `pow()`
calls with `exp()`. This was only tested for the intermediate case.

##### Measurement - Intermediate

`perf stat`:

```
 Performance counter stats for './intermediate-main-O3-ffast-math.out' (5 runs):

          8,566.30 msec task-clock                       #    0.999 CPUs utilized               ( +-  0.46% )
                14      context-switches                 #    1.634 /sec                        ( +- 14.03% )
                 0      cpu-migrations                   #    0.000 /sec                 
                76      page-faults                      #    8.872 /sec                        ( +-  1.05% )
    40,742,157,788      cycles                           #    4.756 GHz                         ( +-  0.12% )  (71.43%)
        90,315,006      stalled-cycles-frontend          #    0.22% frontend cycles idle        ( +-  1.83% )  (71.42%)
   151,045,821,625      instructions                     #    3.71  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.01% )  (71.43%)
    22,017,903,025      branches                         #    2.570 G/sec                       ( +-  0.00% )  (71.43%)
         2,207,376      branch-misses                    #    0.01% of all branches             ( +-  0.54% )  (71.42%)
    46,045,859,935      L1-dcache-loads                 #    5.375 G/sec                       ( +-  0.00% )  (71.43%)
           868,287      L1-dcache-load-misses            #    0.00% of all L1-dcache accesses   ( +-  5.17% )  (71.43%)
   <not supported>      LLC-loads                                                        
   <not supported>      LLC-load-misses                                                  

            8.5754 +- 0.0354 seconds time elapsed  ( +-  0.41% )
```

The number of executed instructions went from `228,149,636,174` (simple `-O3`
case) -> `151,045,821,625`

`perf report`

```
Samples: 467K of event 'cycles:P', Event count (approx.): 41330202364
Overhead  Command          Shared Object                        Symbol
  54.02%  intermediate-ma  libm.so.6                            [.] __cos_fma
  15.87%  intermediate-ma  libm.so.6                            [.] __ieee754_exp_fma
  11.83%  intermediate-ma  libm.so.6                            [.] exp@@GLIBC_2.29
   8.57%  intermediate-ma  intermediate-main-O3-ffast-math.out  [.] f_intermediate
   6.56%  intermediate-ma  intermediate-main-O3-ffast-math.out  [.] integral_riemann
   1.20%  intermediate-ma  libm.so.6                            [.] __exp_finite@GLIBC_2.
```

Note how the overhead of the `exp()` function is much lower than what was seen for
the `pow()` function in previous examples.

`bpftrace`

```
Microseconds in Riemann integral: 8466576
```

<hr>

### Algorithm Modification - Loop Optimisation

The `integral_riemann` code has some inefficiencies- for example, there's
an unecessary multiplication in the body of the hottest loop in the code:

```C
    for (double n = lower_bound; n < upper_bound; n += step) {
        sum += ((integrand(n)) * step);
    }

    return sum;
```

This could be brought outside the loop body without impacting the result, since
all intermediate results are multiplied by this step value.

```
    for (double n = lower_bound; n < upper_bound; n += step) {
        sum += (integrand(n));
    }

    return (sum * step);
```

This is an example (albeit an exceedingly simple one) of how modification of
algorithms can bring performance improvements.

#### Measurement - Simple

`perf stat`

```
 Performance counter stats for './simple-main-rewritten.out' (5 runs):

          6,724.41 msec task-clock                       #    1.000 CPUs utilized               ( +-  0.53% )
                11      context-switches                 #    1.636 /sec                        ( +- 17.01% )
                 0      cpu-migrations                   #    0.000 /sec                 
                76      page-faults                      #   11.302 /sec                        ( +-  0.97% )
    32,688,385,725      cycles                           #    4.861 GHz                         ( +-  0.01% )  (71.43%)
        65,538,629      stalled-cycles-frontend          #    0.20% frontend cycles idle        ( +-  1.32% )  (71.43%)
    91,097,777,304      instructions                     #    2.79  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.02% )  (71.43%)
    11,018,269,724      branches                         #    1.639 G/sec                       ( +-  0.02% )  (71.43%)
         1,770,930      branch-misses                    #    0.02% of all branches             ( +-  0.52% )  (71.43%)
    30,021,332,185      L1-dcache-loads                  #    4.465 G/sec                       ( +-  0.01% )  (71.43%)
           766,880      L1-dcache-load-misses            #    0.00% of all L1-dcache accesses   ( +-  8.55% )  (71.43%)
   <not supported>      LLC-loads                                                        
   <not supported>      LLC-load-misses                                                  

            6.7260 +- 0.0358 seconds time elapsed  ( +-  0.53% )
```

From the base case, the number of instructions executed was reduced from
`94,083,232,371` -> `91,097,777,304`

`perf record`

```
Samples: 362K of event 'cycles:P', Event count (approx.): 33148350337
Overhead  Command          Shared Object                                   Symbol
  82.38%  simple-main-rew  libm.so.6                                       [.] __cos_fma
   9.20%  simple-main-rew  simple-main-rewritten.out                       [.] integral_r
   7.20%  simple-main-rew  simple-main-rewritten.out                       [.] f_simple
```

`bpftrace`

```
Microseconds in Riemann integral: 6764517
```

#### Measurement - Intermediate

`perf stat`:

```
 Performance counter stats for './intermediate-main-rewritten.out' (5 runs):

         14,471.91 msec task-clock                       #    1.000 CPUs utilized               ( +-  0.16% )
                39      context-switches                 #    2.695 /sec                        ( +-  7.93% )
                 0      cpu-migrations                   #    0.000 /sec                 
                75      page-faults                      #    5.182 /sec                        ( +-  0.78% )
    69,618,957,577      cycles                           #    4.811 GHz                         ( +-  0.06% )  (71.43%)
       141,500,856      stalled-cycles-frontend          #    0.20% frontend cycles idle        ( +-  1.99% )  (71.43%)
   232,125,443,276      instructions                     #    3.33  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.01% )  (71.43%)
    24,030,382,686      branches                         #    1.660 G/sec                       ( +-  0.01% )  (71.43%)
         3,811,791      branch-misses                    #    0.02% of all branches             ( +-  0.92% )  (71.43%)
    64,067,695,209      L1-dcache-loads                  #    4.427 G/sec                       ( +-  0.01% )  (71.43%)
         1,671,895      L1-dcache-load-misses            #    0.00% of all L1-dcache accesses   ( +-  4.68% )  (71.42%)
   <not supported>      LLC-loads                                                        
   <not supported>      LLC-load-misses                                                  

           14.4737 +- 0.0228 seconds time elapsed  ( +-  0.16% )
```

The number of instructions compared to the base case went from `235,111,065,770`
-> `232,125,443,276`

`perf record`:

```
Samples: 775K of event 'cycles:P', Event count (approx.): 70555131038
Overhead  Command          Shared Object                    Symbol
  36.03%  intermediate-ma  libm.so.6                        [.] pow@@GLIBC_2.29
  26.39%  intermediate-ma  libm.so.6                        [.] __ieee754_pow_fma
  19.33%  intermediate-ma  libm.so.6                        [.] __cos_fma
   8.18%  intermediate-ma  intermediate-main-rewritten.out  [.] integral_riemann
   8.15%  intermediate-ma  intermediate-main-rewritten.out  [.] f_intermediate
```


`bpftrace`:

```
Microseconds in Riemann integral: 14650106
```

<hr>

### Algorithm Modification - Small Angle Approximation

The performance analysis tools seen have identified that the `cos()` functions
is one of the main hot-points in the code, therefore efforts to speed up
code associated with this function call should improve performance.

One such speed up is to add small angle approximations. This is a concept related
to the trigonometric functions `sin`, `cos` and `tan` The cosine approximation
is as follows for small values of theta:

$$ \cos {\theta} \approx 1 - (\theta ^ 2/2) $$

For very small values of theta, this simplifies further:

$$ \cos {\theta} \approx 1 $$

To quantify what 'small' and 'very small' means, this approximation was explored
in a Python script:

```python
import math

def cosine_approx(theta):
    return(1 - (theta**2)/2)
```

Several values of theta were tested:

| `theta`      | `cos(theta)`      | `1 - (theta^2 / 2)`        |
| ---------- | ----------------- | ---------------------------- |
| 0.001      | 0.9999995         | 0.9999995                    |
| 0.01       | 0.999950          | 0.99995                      |
| 0.05       | 0.998750          | 0.99875                      |
| 0.1        | 0.995004          | 0.995                        |
| 0.2        | 0.980067          | 0.98                         |
| 0.4        | 0.921061          | 0.919999...                  |
| 0.5        | 0.877583          | 0.875                        |

From the table, the values of `0.05` and `0.4` for the 'very small' and 'small'
cases seemed good enough.

A new function was written (and set to be inlined to try remove the impact
of additional function calls on this particular test), and the `f_simple` and
`f_intermediate` functions were rewritten appropriately:

```C
double __attribute__ ((always_inline)) inline cosine_approx(double x) {
    double res;
    // Cosine small angle approximation
    if (x >= -0.05 && x <= 0.05) {
        res = 1;
    } else if (x >= -0.4 && x <= 0.4) {
        res = (1 - (x * x)/2);
    } else {
        res = cos(x);
    }
    return res;
}

double f_simple(double x) {
    return cosine_approx(x);
}

double f_intermediate(double x) {
    double cos_res = cosine_approx(x);
    return (x * pow(M_E, x) * cos_res);
}
```

It should be noted that this optimisation would make less of a difference if the
bounds of integration was increased, i.e if fewer of the inputs met the small
angle condition.

#### Measurement - Simple

Note that the obtained results started deviating from the analytical solution:

```
Riemann:	0.707043
Analytical:	0.707107
```

`perf stat`:

```
 Performance counter stats for './simple-main-cos-smallangle.out' (5 runs):

          5,300.08 msec task-clock                       #    1.000 CPUs utilized               ( +-  0.12% )
                17      context-switches                 #    3.207 /sec                        ( +- 11.25% )
                 0      cpu-migrations                   #    0.000 /sec                 
                76      page-faults                      #   14.339 /sec                        ( +-  0.89% )
    25,570,332,677      cycles                           #    4.825 GHz                         ( +-  0.05% )  (71.42%)
        51,046,515      stalled-cycles-frontend          #    0.20% frontend cycles idle        ( +-  1.04% )  (71.42%)
    77,191,972,384      instructions                     #    3.02  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.02% )  (71.42%)
    11,319,650,092      branches                         #    2.136 G/sec                       ( +-  0.02% )  (71.42%)
         1,391,643      branch-misses                    #    0.01% of all branches             ( +-  0.38% )  (71.44%)
    26,640,218,261      L1-dcache-loads                  #    5.026 G/sec                       ( +-  0.01% )  (71.45%)
           597,515      L1-dcache-load-misses            #    0.00% of all L1-dcache accesses   ( +-  7.77% )  (71.43%)
   <not supported>      LLC-loads                                                        
   <not supported>      LLC-load-misses                                                  

           5.30146 +- 0.00624 seconds time elapsed  ( +-  0.12% )
```

`perf record`:

```
Samples: 283K of event 'cycles:P', Event count (approx.): 25921551458
Overhead  Command          Shared Object                   Symbol
  56.28%  simple-main-cos  simple-main-cos-smallangle.out  [.] f_simple
  24.97%  simple-main-cos  libm.so.6                       [.] __cos_fma
  17.88%  simple-main-cos  simple-main-cos-smallangle.out  [.] integral_riemann
```

The overhead has shifted considerably to `f_simple()` away from `cos()`

`bpftrace`:

```
Microseconds in Riemann integral: 5343617
```

#### Measurement - Intermediate

Again, the numerical output deviated from the expected due to errors in the approximation:

```
Riemann:	0.44258
Analytical:	0.442619
```

`perf stat`:

```
 Performance counter stats for './intermediate-main-cos-smallangle.out' (5 runs):

         14,281.77 msec task-clock                       #    1.000 CPUs utilized               ( +-  0.34% )
                44      context-switches                 #    3.081 /sec                        ( +- 11.26% )
                 0      cpu-migrations                   #    0.000 /sec                 
                75      page-faults                      #    5.251 /sec                        ( +-  0.68% )
    68,270,069,802      cycles                           #    4.780 GHz                         ( +-  0.01% )  (71.42%)
       135,674,491      stalled-cycles-frontend          #    0.20% frontend cycles idle        ( +-  0.53% )  (71.42%)
   218,235,603,025      instructions                     #    3.20  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.01% )  (71.43%)
    24,336,817,280      branches                         #    1.704 G/sec                       ( +-  0.00% )  (71.43%)
         3,701,441      branch-misses                    #    0.02% of all branches             ( +-  0.36% )  (71.44%)
    60,689,239,494      L1-dcache-loads                  #    4.249 G/sec                       ( +-  0.01% )  (71.43%)
         1,503,893      L1-dcache-load-misses            #    0.00% of all L1-dcache accesses   ( +-  2.36% )  (71.43%)
   <not supported>      LLC-loads                                                        
   <not supported>      LLC-load-misses                                                  

           14.2856 +- 0.0479 seconds time elapsed  ( +-  0.34% )
```

`perf record`:

```
Samples: 772K of event 'cycles:P', Event count (approx.): 69175341094
Overhead  Command          Shared Object                         Symbol
  39.64%  intermediate-ma  libm.so.6                             [.] __ieee754_pow_fma
  18.29%  intermediate-ma  libm.so.6                             [.] __cos_fma
  17.79%  intermediate-ma  libm.so.6                             [.] pow@@GLIBC_2.29
  13.12%  intermediate-ma  intermediate-main-cos-smallangle.out  [.] f_intermediate
   4.91%  intermediate-ma  intermediate-main-cos-smallangle.out  [.] integral_riemann
   4.67%  intermediate-ma  intermediate-main-cos-smallangle.out  [.] pow@plt
```

`bpftrace`:

```
Microseconds in Riemann integral: 14392529
```

This shows a speedup, but nowhere near as dramatic as the one in `f_simple()`.

<br>

#### Positive Case

Another optimisation considered was to consider the user case for `x >= 0` only,
since this would reduce the number of comparisons made. This had positive effects
on performance, but introduces limits on use cases for the code. Of course, the
problem could be split up in a way where any negative values are handled by a
different optimised function.

The new code looks like this:

```C
double __attribute__ ((always_inline)) inline cosine_approx(double x) {
    double res;
    // Cosine small angle approximation
    if (x <= 0.05) {
        res = 1;
    else if (x <= 0.4) {
        res = (1 - (x * x)/2);
    } else {
        res = cos(x);
    }
    return res;
}

```

##### Measurement - Simple

`perf stat`:

```
 Performance counter stats for './simple-main-cos-smallangle-positive.out' (5 runs):

          5,037.39 msec task-clock                       #    1.000 CPUs utilized               ( +-  0.48% )
                18      context-switches                 #    3.573 /sec                        ( +- 34.40% )
                 0      cpu-migrations                   #    0.000 /sec                 
                75      page-faults                      #   14.889 /sec                        ( +-  0.90% )
    24,082,388,129      cycles                           #    4.781 GHz                         ( +-  0.05% )  (71.40%)
        42,237,868      stalled-cycles-frontend          #    0.18% frontend cycles idle        ( +-  0.81% )  (71.41%)
    71,366,823,827      instructions                     #    2.96  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.01% )  (71.44%)
     9,382,241,698      branches                         #    1.863 G/sec                       ( +-  0.01% )  (71.45%)
         1,215,278      branch-misses                    #    0.01% of all branches             ( +-  0.59% )  (71.44%)
    24,704,129,288      L1-dcache-loads                  #    4.904 G/sec                       ( +-  0.01% )  (71.44%)
           559,475      L1-dcache-load-misses            #    0.00% of all L1-dcache accesses   ( +-  3.00% )  (71.42%)
   <not supported>      LLC-loads                                                        
   <not supported>      LLC-load-misses                                                  

            5.0388 +- 0.0242 seconds time elapsed  ( +-  0.48% )
```

`perf record`:

```
Samples: 267K of event 'cycles:P', Event count (approx.): 24417293220
Overhead  Command          Shared Object                            Symbol
  37.32%  simple-main-cos  simple-main-cos-smallangle-positive.out  [.] f_simple
  35.62%  simple-main-cos  libm.so.6                                [.] __cos_fma
  17.75%  simple-main-cos  simple-main-cos-smallangle-positive.out  [.] integral_riemann
   9.04%  simple-main-cos  simple-main-cos-smallangle-positive.out  [.] cos@plt
```

`bpftrace`:

```
Microseconds in Riemann integral: 5080937
```

##### Measurement - Intermediate

`perf stat`:

```
 Performance counter stats for './intermediate-main-smallangle-positive.out' (5 runs):

         13,997.15 msec task-clock                       #    1.000 CPUs utilized               ( +-  0.36% )
               289      context-switches                 #   20.647 /sec                        ( +- 52.51% )
                 2      cpu-migrations                   #    0.143 /sec                        ( +- 33.17% )
                77      page-faults                      #    5.501 /sec                        ( +-  1.12% )
    67,219,780,786      cycles                           #    4.802 GHz                         ( +-  0.06% )  (71.43%)
       127,900,502      stalled-cycles-frontend          #    0.19% frontend cycles idle        ( +-  2.95% )  (71.43%)
   212,453,637,442      instructions                     #    3.16  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.01% )  (71.43%)
    22,398,954,888      branches                         #    1.600 G/sec                       ( +-  0.01% )  (71.43%)
         3,429,936      branch-misses                    #    0.02% of all branches             ( +-  1.22% )  (71.43%)
    58,753,448,326      L1-dcache-loads                  #    4.198 G/sec                       ( +-  0.01% )  (71.43%)
         1,996,239      L1-dcache-load-misses            #    0.00% of all L1-dcache accesses   ( +-  4.74% )  (71.42%)
   <not supported>      LLC-loads                                                        
   <not supported>      LLC-load-misses                                                  

           14.0006 +- 0.0510 seconds time elapsed  ( +-  0.36% )
```

`perf record`:

```
Samples: 754K of event 'cycles:P', Event count (approx.): 68122746263
Overhead  Command          Shared Object                              Symbol
  40.86%  intermediate-ma  libm.so.6                                  [.] __ieee754_pow_f
  19.72%  intermediate-ma  libm.so.6                                  [.] pow@@GLIBC_2.29
  19.66%  intermediate-ma  libm.so.6                                  [.] __cos_fma
  10.70%  intermediate-ma  intermediate-main-smallangle-positive.out  [.] f_intermediate
   5.09%  intermediate-ma  intermediate-main-smallangle-positive.out  [.] integral_rieman
   2.92%  intermediate-ma  libm.so.6                                  [.] __pow_finite@GL
```

`bpftrace`:

```
Microseconds in Riemann integral: 14154213
```

<hr>

### Optimising Instruction Cache Access

This section makes use of information and macros from part of [Halvar's LWN series
on memory and performance](https://lwn.net/Articles/255364/). 

An attempt was made to improve branch prediction by reordering the small angle
check and making use of the `__builtin_expect` branch hint. This was placed on
the most taken branch path _for the tested intergral bounds_. This may not apply
if using different integration bounds.

The new function looks like this:

```C
#define likely(expr) __builtin_expect(!!(expr), 1)

double __attribute__ ((always_inline)) inline cosine_approx(double x) {
    double res;
    // Cosine small angle approximation
    if (likely(x <= 0.4)) {
        res = (1 - (x * x)/2);
    } else if (x <= 0.05) {
        res = 1;
    } else {
        res = cos(x);
    }
    return res;
}
```

The code was also compiled with the `-freorder-blocks` flag.

#### Measurement - Simple

`perf stat`:

```
 Performance counter stats for './simple-main-cos-smallangle-likelymacro.out' (5 runs):

          4,940.79 msec task-clock                       #    0.999 CPUs utilized               ( +-  0.28% )
               171      context-switches                 #   34.610 /sec                        ( +- 94.18% )
                 0      cpu-migrations                   #    0.000 /sec                 
                75      page-faults                      #   15.180 /sec                        ( +-  0.78% )
    23,849,673,126      cycles                           #    4.827 GHz                         ( +-  0.11% )  (71.42%)
        47,761,477      stalled-cycles-frontend          #    0.20% frontend cycles idle        ( +-  8.31% )  (71.43%)
    73,416,966,946      instructions                     #    3.08  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.03% )  (71.42%)
     8,936,583,017      branches                         #    1.809 G/sec                       ( +-  0.03% )  (71.43%)
         1,253,011      branch-misses                    #    0.01% of all branches             ( +-  3.72% )  (71.43%)
    24,322,566,217      L1-dcache-loads                  #    4.923 G/sec                       ( +-  0.02% )  (71.44%)
           682,118      L1-dcache-load-misses            #    0.00% of all L1-dcache accesses   ( +- 13.71% )  (71.42%)
   <not supported>      LLC-loads                                                        
   <not supported>      LLC-load-misses                                                  

            4.9435 +- 0.0147 seconds time elapsed  ( +-  0.30% )
```

`perf report`:

```
Samples: 263K of event 'cycles:Pu', Event count (approx.): 24178630728
Overhead  Command          Shared Object                           Symbol
  55.93%  simple-main-sma  simple-main-smallangle-likelymacro.out  [.] integral_riemann
  31.78%  simple-main-sma  simple-main-smallangle-likelymacro.out  [.] f_simple
  12.24%  simple-main-sma  libm.so.6                               [.] __cos_fma
```

`bpftrace`:

```
Microseconds in Riemann integral: 5012777
```

#### Measurement - Intermediate

`perf stat`:

```
 Performance counter stats for './intermediate-main-smallangle-likelymacro.out' (5 runs):

         13,958.08 msec task-clock                       #    0.999 CPUs utilized               ( +-  0.19% )
               883      context-switches                 #   63.261 /sec                        ( +- 33.01% )
                 2      cpu-migrations                   #    0.143 /sec                        ( +- 75.83% )
                75      page-faults                      #    5.373 /sec                        ( +-  1.44% )
    67,045,218,431      cycles                           #    4.803 GHz                         ( +-  0.05% )  (71.42%)
       127,879,489      stalled-cycles-frontend          #    0.19% frontend cycles idle        ( +-  1.49% )  (71.42%)
   214,465,059,223      instructions                     #    3.20  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.00% )  (71.43%)
    21,953,824,530      branches                         #    1.573 G/sec                       ( +-  0.00% )  (71.43%)
         3,461,325      branch-misses                    #    0.02% of all branches             ( +-  1.17% )  (71.43%)
    58,376,508,362      L1-dcache-loads                  #    4.182 G/sec                       ( +-  0.01% )  (71.44%)
         2,236,603      L1-dcache-load-misses            #    0.00% of all L1-dcache accesses   ( +-  4.43% )  (71.43%)
   <not supported>      LLC-loads                                                        
   <not supported>      LLC-load-misses                                                  

           13.9658 +- 0.0257 seconds time elapsed  ( +-  0.18% )
```

`perf report`:

```
Samples: 749K of event 'cycles:P', Event count (approx.): 67925470235
Overhead  Command          Shared Object                                 Symbol
  39.80%  intermediate-ma  libm.so.6                                     [.] __ieee754_po
  21.81%  intermediate-ma  libm.so.6                                     [.] pow@@GLIBC_2
  19.22%  intermediate-ma  libm.so.6                                     [.] __cos_fma
  11.26%  intermediate-ma  intermediate-main-smallangle-likelymacro.out  [.] f_intermedia
   5.96%  intermediate-ma  intermediate-main-smallangle-likelymacro.out  [.] integral_rie
```

`bpftrace`:

```
Microseconds in Riemann integral: 14004255
```

<hr>

### Algorithm Modification - Taylor Expansion

One way of representing certain functions is with a [Taylor series](https://en.wikipedia.org/wiki/Taylor_series). These will be used to in place of the `cos()` and
`pow()` functions in the code. The idea is that perhaps these approximations might
be faster while also being accurate enough for our purposes.

Another reason for doing this is to make it more straightforward to vectorise
the new Taylor expansions using SIMD instructions than it would be to vectorise
the trigonometric/exponential functions (since there are no instrinsics for these
trig functions). This topic is explored in the next section.

The Taylor series of the `cos()` function is:

$$ 1 - x^2/2! + x^4/4! - x^6/6! + ... = \sum_{i=0}^\infty (-1)^i (x^{2i}/(2i)!) $$

The Taylor series of the exponential function is:

$$ 1 + x + x^2/2! + x^3/3! + ... = \sum_{i=0}^\infty x^i/i! $$

A limit of 6 terms was set for the expansion of `cos()`, and 7 for the expansion
of the exponential. This was chosen as a tradeoff between runtime and accuracy.

In C, these functions are implemented as

```C
// Valid for inputs <= 12. Errors ignored
int __attribute__ ((always_inline)) inline factorial_int(int x) {
    if (x == 0) {
        return 1;
    }
    int ret = 1;
    for (int i = 1; i <= x; i++) {
        ret *= i;
    }
    return ret;
}

// Valid for fairly small x due to the potential for the x^2n term to explode
double __attribute__ ((always_inline)) inline taylor_cos(double x) {
    double ret = 0.0;
    double pow_sum = 1.0;

    // 6 term expansion
    int num_terms = 6;
    for (int i = 0; i < num_terms; i++) {
        pow_sum = 1.0;
        for (int n = 0; n < (2 * i); n++) {
            pow_sum *= x;
        }
        // Odd terms have a negative sign
        if ((i & 1)) {
            pow_sum *= (-1);
        }
        ret += (pow_sum / (double)(factorial_int(2 * i)));
    }
    return ret;
}

double __attribute__ ((always_inline)) inline taylor_exp(double x) {
    double ret = 0.0;
    double pow_sum = 1.0;
    int num_terms = 7;
    for (int i = 0; i < num_terms; i++) {
        pow_sum = 1.0;
        for (int n = 0; n < i; n++) {
            pow_sum *= x;
        }
        ret += (pow_sum / (double)factorial_int(i));
    }
    return ret;
}

```

In practice, without optimisations the resulting code was much slower- the
`f_simple` test took about 64 seconds to complete. _With_ `-O3` optimisations
enabled, however, results were much better than using the math library functions.

Some very interesting behaviour was observed here. In the `factorial_int()`
function above, the first branch checking for `x == 0` was redundant- the code 
would've returned the correct results regardless. However, if the check was
removed the resulting assembly output for the function was larger, and took > 3
times longer to execute. With it, the compiler produced smaller, branchless code:

```
00000000004011f0 <f_simple>:
  4011f0:	66 0f 28 c8          	movapd xmm1,xmm0
  4011f4:	f2 0f 10 15 74 0e 00 	movsd  xmm2,QWORD PTR [rip+0xe74]        # 402070 <__dso_handle+0x68>
  4011fb:	00
  4011fc:	f3 0f 7e 25 2c 0e 00 	movq   xmm4,QWORD PTR [rip+0xe2c]        # 402030 <__dso_handle+0x28>
  401203:	00
  401204:	f2 0f 59 c8          	mulsd  xmm1,xmm0
  401208:	f2 0f 59 d1          	mulsd  xmm2,xmm1
  40120c:	f2 0f 59 c8          	mulsd  xmm1,xmm0
  401210:	f2 0f 58 15 30 0e 00 	addsd  xmm2,QWORD PTR [rip+0xe30]        # 402048 <__dso_handle+0x40>
  401217:	00
  401218:	f2 0f 59 c8          	mulsd  xmm1,xmm0
  40121c:	66 0f 28 d9          	movapd xmm3,xmm1
  401220:	f2 0f 5e 1d 28 0e 00 	divsd  xmm3,QWORD PTR [rip+0xe28]        # 402050 <__dso_handle+0x48>
  401227:	00
  401228:	f2 0f 58 da          	addsd  xmm3,xmm2
  40122c:	f2 0f 59 c8          	mulsd  xmm1,xmm0
  401230:	f2 0f 59 c8          	mulsd  xmm1,xmm0
  401234:	66 0f 28 d1          	movapd xmm2,xmm1
  401238:	f2 0f 59 c8          	mulsd  xmm1,xmm0
  40123c:	66 0f 57 d4          	xorpd  xmm2,xmm4
  401240:	f2 0f 5e 15 10 0e 00 	divsd  xmm2,QWORD PTR [rip+0xe10]        # 402058 <__dso_handle+0x50>
  401247:	00
  401248:	f2 0f 58 d3          	addsd  xmm2,xmm3
  40124c:	f2 0f 59 c8          	mulsd  xmm1,xmm0
  401250:	66 0f 28 d9          	movapd xmm3,xmm1
  401254:	f2 0f 5e 1d 04 0e 00 	divsd  xmm3,QWORD PTR [rip+0xe04]        # 402060 <__dso_handle+0x58>
  40125b:	00
  40125c:	f2 0f 58 d3          	addsd  xmm2,xmm3
  401260:	f2 0f 59 c8          	mulsd  xmm1,xmm0
  401264:	f2 0f 59 c1          	mulsd  xmm0,xmm1
  401268:	66 0f 57 c4          	xorpd  xmm0,xmm4
  40126c:	f2 0f 5e 05 f4 0d 00 	divsd  xmm0,QWORD PTR [rip+0xdf4]        # 402068 <__dso_handle+0x60>
  401273:	00
  401274:	f2 0f 58 c2          	addsd  xmm0,xmm2
  401278:	c3                   	ret
  401279:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
```

Decompilation using Ghidra more clearly shows the impressive optimisations made
by the compiler:

```C
double f_simple(double param_1)

{
  double dVar1;
  double dVar2;
  double dVar3;
  
  dVar1 = param_1 * param_1 * param_1 * param_1;
  dVar2 = dVar1 * param_1 * param_1;
  dVar3 = dVar2 * param_1 * param_1;
  return -(param_1 * dVar3 * param_1) / 3628800.0 +
         -dVar2 / 720.0 + dVar1 / 24.0 + param_1 * param_1 * -0.5 + 1.0 + dVar3 / 40320.0;
}
```

Contrast this with code produced if the seemingly unrelated, redundant check is
removed:

```C
double f_simple(double x)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  double dVar6;
  double dVar7;
  
  iVar4 = 0;
  dVar7 = 0.0;
  uVar5 = 0;
  iVar2 = 1;
  do {
    dVar6 = 1.0;
    if (iVar4 != 0) {
      dVar6 = x * x;
      if ((((iVar4 == 2) || (dVar6 = dVar6 * x * x, iVar4 == 4)) ||
          (dVar6 = dVar6 * x * x, iVar4 == 6)) ||
         ((dVar6 = dVar6 * x * x, iVar4 == 8 || (dVar6 = dVar6 * x, iVar4 != 10)))) {
        if ((uVar5 & 1) != 0) {
          dVar6 = -dVar6;
        }
      }
      else {
        dVar6 = dVar6 * x;
        if ((uVar5 & 1) != 0) {
          dVar6 = -dVar6;
        }
      }
      iVar1 = 1;
      uVar3 = 1;
      do {
        uVar3 = uVar3 * iVar1;
        iVar1 = iVar1 + 1;
      } while (iVar2 != iVar1);
      dVar6 = dVar6 / (double)uVar3;
    }
    uVar5 = uVar5 + 1;
    dVar7 = dVar7 + dVar6;
    iVar4 = iVar4 + 2;
    iVar2 = iVar2 + 2;
  } while (uVar5 != 6);
  return dVar7;
}
```

I'm not entirely sure what caused this behaviour (perhaps the compiler could
make better assumptions about the code?), but it _was_ interesting to see.

All measurements are done with the optimised version (with redundant check).

#### Measurement - Simple

Accuracy seems good:

```
Riemann:	0.707107
Analytical:	0.707107
```

`perf stat`:

```
 Performance counter stats for './simple-main-taylor-o3.out' (5 runs):

          3,674.00 msec task-clock                       #    1.000 CPUs utilized               ( +-  0.56% )
                11      context-switches                 #    2.994 /sec                        ( +-  6.80% )
                 0      cpu-migrations                   #    0.000 /sec                 
                75      page-faults                      #   20.414 /sec                        ( +-  0.90% )
    18,085,666,563      cycles                           #    4.923 GHz                         ( +-  0.01% )  (71.42%)
        35,233,557      stalled-cycles-frontend          #    0.19% frontend cycles idle        ( +-  1.07% )  (71.42%)
    41,046,867,512      instructions                     #    2.27  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.01% )  (71.41%)
     3,008,201,839      branches                         #  818.780 M/sec                       ( +-  0.01% )  (71.42%)
           882,609      branch-misses                    #    0.03% of all branches             ( +-  0.49% )  (71.46%)
    11,013,661,662      L1-dcache-loads                  #    2.998 G/sec                       ( +-  0.01% )  (71.45%)
           411,099      L1-dcache-load-misses            #    0.00% of all L1-dcache accesses   ( +-  4.01% )  (71.42%)
   <not supported>      LLC-loads                                                        
   <not supported>      LLC-load-misses                                                  

            3.6756 +- 0.0206 seconds time elapsed  ( +-  0.56% )
```

`perf report`:

```
Samples: 195K of event 'cycles:P', Event count (approx.): 18280118774
Overhead  Command          Shared Object              Symbol
  63.30%  simple-main-tay  simple-main-taylor-o3.out  [.] f_simple
  36.42%  simple-main-tay  simple-main-taylor-o3.out  [.] integral_riemann
```

`bpftrace`:

```
Microseconds in Riemann integral: 3701438
```

#### Measurement - Intermediate

The accuracy took a hit for the intermediate version:

```
Riemann:	0.442617
Analytical:	0.442619
```

`perf stat`:

```
 Performance counter stats for './intermediate-main-taylor-o3.out' (5 runs):

          9,629.54 msec task-clock                       #    1.000 CPUs utilized               ( +-  0.65% )
                25      context-switches                 #    2.596 /sec                        ( +- 10.32% )
                 1      cpu-migrations                   #    0.104 /sec                        ( +- 48.99% )
                75      page-faults                      #    7.789 /sec                        ( +-  1.37% )
    46,336,699,762      cycles                           #    4.812 GHz                         ( +-  0.58% )  (71.43%)
       121,653,732      stalled-cycles-frontend          #    0.26% frontend cycles idle        ( +-  7.55% )  (71.43%)
   237,080,118,269      instructions                     #    5.12  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.01% )  (71.43%)
    45,024,959,424      branches                         #    4.676 G/sec                       ( +-  0.02% )  (71.43%)
         2,268,957      branch-misses                    #    0.01% of all branches             ( +-  1.25% )  (71.43%)
    11,033,769,118      L1-dcache-loads                  #    1.146 G/sec                       ( +-  0.01% )  (71.43%)
           936,905      L1-dcache-load-misses            #    0.01% of all L1-dcache accesses   ( +-  5.39% )  (71.43%)
   <not supported>      LLC-loads                                                        
   <not supported>      LLC-load-misses                                                  

            9.6312 +- 0.0620 seconds time elapsed  ( +-  0.64% )
```

`perf report`:

```
Samples: 520K of event 'cycles:P', Event count (approx.): 47339270492
Overhead  Command          Shared Object                    Symbol
  93.65%  intermediate-ma  intermediate-main-taylor-o3.out  [.] f_intermediate
   6.09%  intermediate-ma  intermediate-main-taylor-o3.out  [.] integral_riemann
```

`bpftrace`:

```
Microseconds in Riemann integral: 9660417
```

What's interesting to see here is that this caused more instructions to be
executed than the base case (`237,113,434,810` vs `235,111,065,770`), yet
execution was significantly faster. There were also less branch misses
(`45,040` vs `3,867,468`), and less L1-dache-loads (`11,016,800,665`
vs `65,087,953,018`) and dcache misses (`3,066` vs `1,848,541`). This shows that
the lower amount of branch misses and better cache usage has
significant performance implications.

<hr>

### SIMD Instructions

This section looks at 'Single Instruction, Multiple Data' (SIMD) instructions to
perform some parallel processing of data on a single core.

These extensions use special, high width registers (128, 256, 512 bits wide) to
store multiple pieces of data (e.g. several `int`s) and perform the same operation
on all pieces of the data at the same time.

The [Algorithmica web book has a section on SIMD parallelism](https://en.algorithmica.org/hpc/simd/)
along with [Tuomas Tonteri's blog](http://sci.tuomastonteri.fi/programming/sse)
are some references that will be used for this section, along with the
[Intel intrinsics reference](https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#techs=AVX_512&ig_expand=21),
which offers descriptions of every intrinsic that can be used to access this SIMD
functionality. The [Agner blog on optimizing C++](https://agner.org/optimize/optimizing_cpp.pdf)
also has a good section on the topic.

This section will look at fairly simple uses of AVX-512 intrinsics for the most
part.

The target code that will be vectorised will be the Taylor series for the cosine
and exponential functions, seen in the previous section. This is where it made the
most sense to start, since there were no simple AVX intrinsics for dealing with
cosine or exponential operations- they _can_ be found in the Intel instrinsics
reference, however these don't have corresponding instructions, and actually
seem to be functions written for Intel's Short Vector Math Library (SVML). There
is also Intel's oneAPI toolkit that also provides this functionality somewhere
inside. This is briefly explored in a subsection, but is not used for the tested
code.

<br>

#### -mavx Flag

When compiling with the `-mavx` flag (but without manaully vectorising anything), the compiler emits vector version of some
instructions, such as moves and multiplications. This can be seen by comparing
the instructions at the start of the `f_simple` function with and without this
flag (with `-O3`):

```
00000000004011e0 <f_simple>:
  4011e0:	66 0f 28 c8          	movapd xmm1,xmm0
  4011e4:	f2 0f 10 15 84 0e 00 	movsd  xmm2,QWORD PTR [rip+0xe84]        # 402070 <__dso_handle+0x68>
  4011eb:	00
  4011ec:	f3 0f 7e 25 3c 0e 00 	movq   xmm4,QWORD PTR [rip+0xe3c]        # 402030 <__dso_handle+0x28>
  4011f3:	00
  4011f4:	f2 0f 59 c8          	mulsd  xmm1,xmm0
  4011f8:	f2 0f 59 d1          	mulsd  xmm2,xmm1
  4011fc:	f2 0f 59 c8          	mulsd  xmm1,xmm0
  401200:	f2 0f 58 15 40 0e 00 	addsd  xmm2,QWORD PTR [rip+0xe40] 
```

```
00000000004011e0 <f_simple>:
  4011e0:	c5 fb 59 c8          	vmulsd xmm1,xmm0,xmm0
  4011e4:	c5 fa 7e 25 44 0e 00 	vmovq  xmm4,QWORD PTR [rip+0xe44]        # 402030 <__dso_handle+0x28>
  4011eb:	00
  4011ec:	c5 f3 59 15 7c 0e 00 	vmulsd xmm2,xmm1,QWORD PTR [rip+0xe7c]        # 402070 <__dso_handle+0x68>
  4011f3:	00
  4011f4:	c5 eb 58 15 4c 0e 00 	vaddsd xmm2,xmm2,QWORD PTR [rip+0xe4c]        # 402048 <__dso_handle+0x40>
```

##### Measurement - Simple

`perf stat`:

```
 Performance counter stats for './simple-main-taylor-o3-mavx.out' (5 runs):

          3,606.90 msec task-clock                       #    1.000 CPUs utilized               ( +-  0.17% )
                 5      context-switches                 #    1.386 /sec                        ( +- 18.55% )
                 0      cpu-migrations                   #    0.000 /sec                 
                74      page-faults                      #   20.516 /sec                        ( +-  1.08% )
    18,086,939,772      cycles                           #    5.015 GHz                         ( +-  0.05% )  (71.40%)
        33,414,750      stalled-cycles-frontend          #    0.18% frontend cycles idle        ( +-  3.31% )  (71.41%)
    36,035,029,568      instructions                     #    1.99  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.01% )  (71.44%)
     3,007,083,389      branches                         #  833.703 M/sec                       ( +-  0.01% )  (71.45%)
           869,494      branch-misses                    #    0.03% of all branches             ( +-  1.70% )  (71.45%)
    11,011,720,042      L1-dcache-loads                  #    3.053 G/sec                       ( +-  0.01% )  (71.44%)
           400,941      L1-dcache-load-misses            #    0.00% of all L1-dcache accesses   ( +-  6.25% )  (71.42%)
   <not supported>      LLC-loads                                                        
   <not supported>      LLC-load-misses                                                  

           3.60840 +- 0.00609 seconds time elapsed  ( +-  0.17% )
```

`perf report`:

```
Samples: 193K of event 'cycles:P', Event count (approx.): 18281519624
Overhead  Command          Shared Object                   Symbol
  60.48%  simple-main-tay  simple-main-taylor-o3-mavx.out  [.] f_simple
  39.29%  simple-main-tay  simple-main-taylor-o3-mavx.out  [.] integral_riemann
```

`bpftrace`:

```
Microseconds in Riemann integral: 3694076
```


##### Measurement - Intermediate

`perf stat`:

```
 Performance counter stats for './intermediate-main-taylor-o3-mavx.out' (5 runs):

          8,314.72 msec task-clock                       #    1.000 CPUs utilized               ( +-  0.58% )
                23      context-switches                 #    2.766 /sec                        ( +- 12.78% )
                 2      cpu-migrations                   #    0.241 /sec                        ( +- 75.17% )
                76      page-faults                      #    9.140 /sec                        ( +-  1.22% )
    40,730,214,596      cycles                           #    4.899 GHz                         ( +-  0.10% )  (71.42%)
     2,527,830,017      stalled-cycles-frontend          #    6.21% frontend cycles idle        ( +- 40.47% )  (71.42%)
   128,107,924,611      instructions                     #    3.15  insn per cycle       
                                                  #    0.02  stalled cycles per insn     ( +-  0.01% )  (71.43%)
    25,027,267,159      branches                         #    3.010 G/sec                       ( +-  0.01% )  (71.44%)
         1,980,134      branch-misses                    #    0.01% of all branches             ( +-  0.36% )  (71.44%)
    11,027,966,294      L1-dcache-loads                  #    1.326 G/sec                       ( +-  0.01% )  (71.44%)
           856,208      L1-dcache-load-misses            #    0.01% of all L1-dcache accesses   ( +-  5.57% )  (71.43%)
   <not supported>      LLC-loads                                                        
   <not supported>      LLC-load-misses                                                  

            8.3161 +- 0.0480 seconds time elapsed  ( +-  0.58% )
```

`perf report`:

```
Samples: 452K of event 'cycles:P', Event count (approx.): 41373441281
Overhead  Command          Shared Object                         Symbol
  89.43%  intermediate-ma  intermediate-main-taylor-o3-mavx.out  [.] f_intermediate
  10.32%  intermediate-ma  intermediate-main-taylor-o3-mavx.out  [.] integral_riemann
```

`bpftrace`:

```
Microseconds in Riemann integral: 8420865
```

An interesting consequence of the generation of these vector instruction is that
not as many instructions ended up being executed, however this did not correspond
with comparitively as much of a performance boost- indeed, the `simple` example
executed at 1.99 instructions per cycle vs. 2.27 for the run without `-mavx`,
and the `intermediate` example ran at 3.15 instructions/second vs the previous
run at 5.12.

<br>

#### AVX-512 Rewrite

This section looks into converting the existing code into a vectorised version.

##### Factorial

Although entirely unecessary, converting the factorial function to a vector
version was a fun puzzle exercise in perusing the intrinsics list to find useful
ones that would help in implementing this functionality.

The algorithm goes something like

- Load a 512bit vector containing the numbers from x = 1 -> 12 (the maximum supported value for this function), with the unused elements set to 1
- Compare the vector to the factorial value argument, and use this to generate a vector mask that specifies which elements from the number vector to use
- Use the mask to set any unwanted values in the number vector to 1
- Perform a reduction on the modified number vector, multiplying all its elements and summing

In C, this looks like:

```C
int factorial_int_avx(int x) {
    if (x == 0) {
        return 1;
    }

    const int all_int_array[16] __attribute__ ((aligned (64))) = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 1, 1, 1, 1};

    __m512i all_ints = _mm512_load_epi32(all_int_array);
    __m512i all_ones = _mm512_set1_epi32(1);

    // Create a vector with all elements set to x, and compare against the all int vector
    __m512i x_vec = _mm512_set1_epi32(x);

    // This mask selects all elements less or equal to x
    __mmask16 factorial_mask = _mm512_cmple_epi32_mask(all_ints, x_vec);

    // Set unused elements to 1, then reduce
    all_ints = _mm512_mask_blend_epi32(factorial_mask, all_ones, all_ints);
    return _mm512_reduce_mul_epi32(all_ints);
}
```

Out of interest, this was timed against the old implementation using the
`TIME_FUNC` macro from the measurement section. The test code compares the
average time taken to execute each of the factorial functions, averaged over
100 million runs (compiled with `-O3`). 

```C

    double time_res = 0.0;
    double time_res_avx = 0.0;
    int count = 100000000;
    for (int i = 0; i < count; i++) {
        time_res += TIME_FUNC(factorial_int(12));
        time_res_avx += TIME_FUNC(factorial_int_avx(12));
    }
    time_res /= count;
    time_res_avx /= count;

    printf("Normal: %g | avx: %g\n", time_res, time_res_avx);

```

The two implementations did not seem to differ very much in execution time:

```
Normal: 0.0164651 | avx: 0.0164653
```

When compiled without `-O3`, however, the AVX code was between 2-3 times slower.

Despite the results above, when this code was ran in place in of the regular factorial
code within the `f_simple` test case, it took significantly longer to run overall. 
The number of instructions/cycles taken was higher, but the L1-dcache and L1-icache
misses and branch misseses seemed less than the code running the
non-vectorised factorial code.

Looking at the objdump and Ghidra output, it seemed the compiler had a much easier time
optimising the case of non-AVX factorial code in conjunction with the vectorised
Taylor series code.

<br>

##### Taylor Series

The Taylor series functions were adjusted to take a vector of inputs and return
a vector of the corresponding outputs, i.e. it performs the Taylor expansion
for each of the input elements.

The main loop for the cosine expansion was mostly directly translated to use
vectors instead- note the set up of the `pow_sum` accumulator as a vector
with the number `1.0` for each entry, and similarly for the vector of `-1.0`
values.

```
  __m512d ret = _mm512_setzero_pd();
  __m512d negative_1 = _mm512_set1_pd(-1.0);
  __m512d pow_sum;

  // 6 term expansion
  int num_terms = 6;
  for (int i = 0; i < num_terms; i++) {

      pow_sum = _mm512_set1_pd(1.0);
      for (int n = 0; n < (2 * i); n++) {
          pow_sum = _mm512_mul_pd(pow_sum, x);
      }

      // Odd terms have a negative sign
      if ((i & 1)) {
          pow_sum = _mm512_mul_pd(pow_sum, negative_1);
      }

      double factorial_divisor_d = (double)factorial_int(2 * i);
      __m512d factorial_divisor_vec = _mm512_set1_pd(factorial_divisor_d);
      pow_sum = _mm512_div_pd(pow_sum, factorial_divisor_vec);

      ret = _mm512_add_pd(ret, pow_sum);
  }
  return ret;
```

When handling the division of the factorial, the first pass seen above performs
a division operation on the vector.

I had some intuition that division instructions were slower than multiplication
ones, so one optimisation that made sense to make here was to work with the
inverse of the factorial and perform a multiplication on the vector instead:

```C
double factorial_divisor_d = 1 / (double)factorial_int(2 * i);
__m512d factorial_divisor_vec = _mm512_set1_pd(factorial_divisor_d);
pow_sum = _mm512_mul_pd(pow_sum, factorial_divisor_vec);
```

This had a fairly dramatic impact on how fast the code ran - ~920,000 microseconds
with the vector division, and ~420,000 microseconds with the vector multiplication
(these were intermediate measurements made when tinkering with various parts of
the algorithm).

The vector version of the Taylor expansion for the exponential function was
created in almost the exact same way:

```
__m512d __attribute__ ((always_inline)) inline taylor_exp(__m512d x) {
    __m512d ret = _mm512_setzero_pd();
    __m512d pow_sum;

    int num_terms = 7;
    for (int i = 0; i < num_terms; i++) {
        pow_sum = _mm512_set1_pd(1.0);
        for (int n = 0; n < i; n++) {
            pow_sum = _mm512_mul_pd(pow_sum, x);
        }

        double factorial_divisor_d = 1/(double)factorial_int(i);
        __m512d factorial_divisor_vec = _mm512_set1_pd(factorial_divisor_d);
        pow_sum = _mm512_mul_pd(pow_sum, factorial_divisor_vec);

        ret = _mm512_add_pd(ret, pow_sum);
    }
    return ret;
}
```
<br>

##### Riemann Integral

Vectorisation of the `integral_riemann()` function was undertaken with the
goal of performing the summation loop with a full 512 bit vector of
8 doubles at a time. Since the integrand function now takes a vector, an argument
vector was constructed for this purpose and filled with the first 8 arguments to
the integrand (creating an assumption that `split` will be greater than 8). Note
the alignment requirements for the array is specified by the `_mm512_load_pd()`
instrinsic.

```C
unsigned int num_vals_vec = sizeof(__m512d)/sizeof(double);

double vec_args_array[sizeof(__m512d)] __attribute__ ((aligned (64))) = {0};
double cur_val = lower_bound;

for (unsigned int i = 0; i < num_vals_vec; i++) {
  vec_args_array[i] = cur_val;
  cur_val += step;
}

__m512d arg_vec = _mm512_load_pd(vec_args_array);
```

In the summation loop, the argument vector is incremented by a static value to
advance it to the next 8 elements. This is done by constructing a vector filled
with this static value:

```C
__m512d arg_vec_step = _mm512_set1_pd(step * num_vals_vec);
```

One potential problem that had to be considered was the ability to
overshoot/undershoot the upper bound since argument advancements were made
8 elements at a time. This was mostly hand-waved away by adjusting the `split`
value downwards to be a multiple of 8.
Given the large `split` values generally used, this should have a negligible
effect on accuracy (the tested `split` value of 1 billion is already divisible by 8, so really there's no effect at all for the tested case).

```C
unsigned int split_remainder = (unsigned int)split % num_vals_vec;
double step = (upper_bound - lower_bound) / (split - (double)split_remainder);
```

For the main summation loop, a summation vector holds the incremental results
from each calculation, and the argument vector is advanced to the next set of inputs. Note the multiplication of the `step` value was moved to the end of the
function to avoid the extra unnecessary multiplication in the hot loop.
The loop now looked like:

```C
for (double n = lower_bound; n < upper_bound; n += (step * sizeof(double))) {
    sum_vec = _mm512_add_pd(sum_vec, integrand(arg_vec));
    arg_vec = _mm512_add_pd(arg_vec, arg_vec_step);
}
```

However, because of the argument vector it was no longer required to perform
an unecessary arithmetic operation to increment `n` since the same operation
is already performed on `arg_vec`, and the required value could just be extracted
from there (really the `n` variable isn't needed at all anymore, however it
was kept for clarity).

Thus the loop can be adjusted to:

```C
double n = lower_bound;
while (n < upper_bound) { 
    sum_vec = _mm512_add_pd(sum_vec, integrand(arg_vec));
    arg_vec = _mm512_add_pd(arg_vec, arg_vec_step);
    n = arg_vec[0];
}
```

Finally, a reduction is made on the summation vector to obtain a sum of its
elements, and a final multiplication by the step value was made.

```C
sum = _mm512_reduce_add_pd(sum_vec);
sum *= step;
```

##### Measurement - Simple

Accuracy is still good:

```
Riemann:	0.707107
Analytical:	0.707107
```

`perf stat`:

```
 Performance counter stats for './simple-main-taylor-o3-vectorised.out' (5 runs):

            415.85 msec task-clock                       #    0.997 CPUs utilized               ( +-  0.29% )
                 1      context-switches                 #    2.405 /sec                        ( +- 48.99% )
                 0      cpu-migrations                   #    0.000 /sec                 
                74      page-faults                      #  177.947 /sec                        ( +-  1.01% )
     2,037,689,928      cycles                           #    4.900 GHz                         ( +-  0.09% )  (71.35%)
         5,394,720      stalled-cycles-frontend          #    0.26% frontend cycles idle        ( +-  7.80% )  (71.35%)
     3,376,218,778      instructions                     #    1.66  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.04% )  (71.36%)
       375,689,939      branches                         #  903.419 M/sec                       ( +-  0.04% )  (71.36%)
           135,414      branch-misses                    #    0.04% of all branches             ( +-  2.88% )  (71.49%)
     1,626,207,583      L1-dcache-loads                  #    3.911 G/sec                       ( +-  0.06% )  (71.61%)
            60,058      L1-dcache-load-misses            #    0.00% of all L1-dcache accesses   ( +-  4.62% )  (71.48%)
   <not supported>      LLC-loads                                                        
   <not supported>      LLC-load-misses                                                  

           0.41713 +- 0.00127 seconds time elapsed  ( +-  0.31% )
```

`perf report`:

```
Samples: 22K of event 'cycles:P', Event count (approx.): 2058542834
Overhead  Command          Shared Object                         Symbol
  63.08%  simple-main-tay  simple-main-taylor-o3-vectorised.out  [.] f_simple
  36.54%  simple-main-tay  simple-main-taylor-o3-vectorised.out  [.] integral_riemann
```

`bpftrace`:

```
Microseconds in Riemann integral: 412555
```

These are some fairly dramatic results, considering the base case ran in `6,847,828` microseconds. Note that the instructions executed per
cycle is the lowest seen so far- these vector instructions seem to take longer
to execute, but work much more efficiently overall.

Significantly fewer branches and L1-dcache loads were made (with lower
corresponding miss counts), which probably contributed to the performance boost.

Fewer instruction cache misses may also have helped with the performance boost.
This value was measured using `perf stat -e L1-icache-loads,L1-icache-misses`
for the base Taylor series example with `-O3` to compare:

```
Performance counter stats for './taylor-series/simple-main-taylor-o3.out' (5 runs):

            62,150      L1-icache-loads:u                                                       ( +- 15.04% )
             1,291      L1-icache-misses:u               #    2.08% of all L1-icache accesses   ( +- 13.88% )

            3.6114 +- 0.0185 seconds time elapsed  ( +-  0.51% )
```

For the vectorised code:

```
 Performance counter stats for './simple-main-taylor-o3-vectorised.out' (5 runs):

            35,134      L1-icache-loads:u                                                       ( +-  0.94% )
               319      L1-icache-misses:u               #    0.91% of all L1-icache accesses   ( +-  3.17% )

           0.41854 +- 0.00195 seconds time elapsed  ( +-  0.47% )
```

##### Measurement - Intermediate

Accuracy was the same as the other Taylor series tests:

```
Riemann:	0.442617
Analytical:	0.442619
```

`perf stat`:

```
 Performance counter stats for './intermediate-main-taylor-o3-vectorised.out' (5 runs):

            558.06 msec task-clock                       #    0.997 CPUs utilized               ( +-  0.35% )
                 0      context-switches                 #    0.000 /sec                 
                 0      cpu-migrations                   #    0.000 /sec                 
                76      page-faults                      #  136.186 /sec                        ( +-  0.53% )
     2,749,267,305      cycles                           #    4.926 GHz                         ( +-  0.19% )  (71.33%)
         6,555,087      stalled-cycles-frontend          #    0.24% frontend cycles idle        ( +-  7.34% )  (71.33%)
     4,753,831,520      instructions                     #    1.73  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.05% )  (71.32%)
       376,151,059      branches                         #  674.032 M/sec                       ( +-  0.02% )  (71.49%)
           171,299      branch-misses                    #    0.05% of all branches             ( +-  1.46% )  (71.67%)
     1,878,630,992      L1-dcache-loads                  #    3.366 G/sec                       ( +-  0.06% )  (71.51%)
            64,094      L1-dcache-load-misses            #    0.00% of all L1-dcache accesses   ( +-  7.82% )  (71.34%)
   <not supported>      LLC-loads                                                        
   <not supported>      LLC-load-misses                                                  

           0.55951 +- 0.00219 seconds time elapsed  ( +-  0.39% )
```

`perf report`:

```
Samples: 29K of event 'cycles:P', Event count (approx.): 2775757963
Overhead  Command          Shared Object                               Symbol
  76.82%  intermediate-ma  intermediate-main-taylor-o3-vectorised.out  [.] f_intermediate
  22.86%  intermediate-ma  intermediate-main-taylor-o3-vectorised.out  [.] integral_riema
```

`bpftrace`:

```
Microseconds in Riemann integral: 552366
```

This is even more of a dramatic change than the previous one! The notes on fewer branches/cache misses are more or less the same as the `f_simple` example.

<br>

#### Comparison of Some Vector Libraries

Since operations like trigonometric functions are unavailable as intrinsics,
it was interesting to explore some libraries that provide equivalent functionality
using SIMD instructions.

None of these were incorporated into the test code, instead a small program
was written for each, with the loose objective of running 2 billion cosine
operations just to have some sort of baseline to compare. Performance of these
libraries for real workloads could vary drastically.

<br>

##### Sleef Vectorised Math Library

The Sleef website provides a [user guide](https://sleef.org/1-user-guide/) to get
up and running, and the git repo provides some [usage references](https://github.com/shibatch/sleef/tree/master/docs/2-references).

Sleef was available as a package on Fedora 40, and was installed in this way.
Results may have been different if it were compiled manually.

The only vector size supported by the library appears to be 128 bits.

Test code:

```C
#include <sleef.h>

#define COUNT 1000000000

void sleef_example() {
   __m128d x = {M_PI/4, M_PI/8};
   for (int i = 0; i < COUNT; i++) {
      x = Sleef_cosd2_u35(x);
   }
   printf("x: %g\n", x[0]);
}
```

Compiling:

```
$ gcc test.c -mavx -Wall -O3 -lsleef
```

Testing:

```
$ perf stat -d -r 5 ./a.out

 Performance counter stats for './a.out' (5 runs):

         15,582.46 msec task-clock:u                     #    1.000 CPUs utilized               ( +-  0.43% )
                 0      context-switches:u               #    0.000 /sec                 
                 0      cpu-migrations:u                 #    0.000 /sec                 
                76      page-faults:u                    #    4.877 /sec                        ( +-  0.64% )
    77,213,872,587      cycles:u                         #    4.955 GHz                         ( +-  0.01% )  (71.43%)
        12,905,432      stalled-cycles-frontend:u        #    0.02% frontend cycles idle        ( +-  2.98% )  (71.43%)
    87,007,752,828      instructions:u                   #    1.13  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.00% )  (71.43%)
     6,000,880,221      branches:u                       #  385.105 M/sec                       ( +-  0.01% )  (71.43%)
            42,976      branch-misses:u                  #    0.00% of all branches             ( +-  1.72% )  (71.43%)
    20,003,368,195      L1-dcache-loads:u                #    1.284 G/sec                       ( +-  0.00% )  (71.42%)
            31,716      L1-dcache-load-misses:u          #    0.00% of all L1-dcache accesses   ( +- 15.47% )  (71.43%)
   <not supported>      LLC-loads:u                                                      
   <not supported>      LLC-load-misses:u                                                

           15.5848 +- 0.0675 seconds time elapsed  ( +-  0.43% )
```

<br>

##### Intel oneAPI

Intel provides several [toolkits](https://www.intel.com/content/www/us/en/developer/tools/oneapi/toolkits.html#gs.i2u2jo)
developing applications.

The [Math Kernel Library](https://www.intel.com/content/www/us/en/developer/tools/oneapi/onemkl.html#gs.i2u3op)
part of this package was used for the test. This library has a
[developer reference](https://www.intel.com/content/www/us/en/docs/onemkl/developer-reference-c/2025-0/overview.html) PDF. There's quite an overwhelming amount
of functionality provided with the toolkit.

Test code:

```
#include <mkl.h>

#define COUNT 1000000000

void intel_oneapi_example() {
   double x[8] = {M_PI/4, M_PI/8, M_PI/4, M_PI/8, M_PI/4, M_PI/8, M_PI/4, M_PI/8};
   for (int i = 0; i < (COUNT/4); i++) {
      vdCos(8, x, x);
   }
   printf("x: %g\n", x[0]);
}
```

Compiling:

```
$ icpx -fsycl test.c -Wall -I/opt/intel/oneapi/2025.0/include -L/opt/intel/oneapi/mkl/latest/lib/ -lmkl_core -lpthread -lm -lmkl_intel_lp64 -lmkl_sequential -O3
```

Testing:

```
$ perf stat -d -r 5 ./a.out

 Performance counter stats for './a.out' (5 runs):

          8,739.14 msec task-clock:u                     #    1.000 CPUs utilized               ( +-  1.03% )
                 0      context-switches:u               #    0.000 /sec                 
                 0      cpu-migrations:u                 #    0.000 /sec                 
               978      page-faults:u                    #  111.910 /sec                        ( +-  0.06% )
    42,246,816,822      cycles:u                         #    4.834 GHz                         ( +-  0.13% )  (71.42%)
       851,872,095      stalled-cycles-frontend:u        #    2.02% frontend cycles idle        ( +-  1.79% )  (71.42%)
   139,865,949,385      instructions:u                   #    3.31  insn per cycle       
                                                  #    0.01  stalled cycles per insn     ( +-  0.03% )  (71.43%)
    13,041,119,650      branches:u                       #    1.492 G/sec                       ( +-  0.02% )  (71.44%)
           195,799      branch-misses:u                  #    0.00% of all branches             ( +-  7.94% )  (71.44%)
    40,684,242,524      L1-dcache-loads:u                #    4.655 G/sec                       ( +-  0.09% )  (71.43%)
           252,424      L1-dcache-load-misses:u          #    0.00% of all L1-dcache accesses   ( +- 14.17% )  (71.42%)
   <not supported>      LLC-loads:u                                                      
   <not supported>      LLC-load-misses:u                                                

            8.7403 +- 0.0897 seconds time elapsed  ( +-  1.03% )
```
<br>

##### Agner Vector Class Library

Agner's [vector class library](https://github.com/vectorclass/version2) for C++
is implemented in a set of headers. The user manual can be found
[here](https://www.agner.org/optimize/vcl_manual.pdf). This library includes
several helpful functions for performing vector operations.

This was the fastest of the tested libraries for the toy example code.

The test code:

```C
#include "vectormath_trig.h"
#include "vectorclass.h"

#define COUNT 1000000000

double vectorclass_lib_example() {
   Vec8d x(M_PI/4, M_PI/8, M_PI/4, M_PI/8, M_PI/4, M_PI/8, M_PI/4, M_PI/8);
   for (int i = 0; i < (COUNT / 4); i++) {
      x = cos(x);
   }
   printf("x: %g\n", x[0]);
}
```

Compiling:

```
$ g++ test.c -Wall -I{PATH_TO_VECTORCLASS_HEADERS} -O3 -mavx
```

Testing:

```
$ perf stat -d -r 5 ./a.out

 Performance counter stats for './a.out' (5 runs):

          2,879.75 msec task-clock:u                     #    0.999 CPUs utilized               ( +-  0.78% )
                 0      context-switches:u               #    0.000 /sec                 
                 0      cpu-migrations:u                 #    0.000 /sec                 
               139      page-faults:u                    #   48.268 /sec                        ( +-  0.18% )
    14,268,214,657      cycles:u                         #    4.955 GHz                         ( +-  0.03% )  (71.43%)
         3,339,002      stalled-cycles-frontend:u        #    0.02% frontend cycles idle        ( +-  8.53% )  (71.44%)
    18,500,034,516      instructions:u                   #    1.30  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.01% )  (71.43%)
       250,790,743      branches:u                       #   87.088 M/sec                       ( +-  0.01% )  (71.44%)
            27,218      branch-misses:u                  #    0.01% of all branches             ( +-  0.67% )  (71.44%)
     4,251,397,772      L1-dcache-loads:u                #    1.476 G/sec                       ( +-  0.02% )  (71.41%)
             3,833      L1-dcache-load-misses:u          #    0.00% of all L1-dcache accesses   ( +- 50.75% )  (71.41%)
   <not supported>      LLC-loads:u                                                      
   <not supported>      LLC-load-misses:u                                                

            2.8815 +- 0.0228 seconds time elapsed  ( +-  0.79% )
```

<hr>

### Honorable Mention: Memory Access Order

This section is a small honorable performance mention that was not explored in
the test code. It recreates some of the concepts talked about in
[Ulrich Drepper's writeups on memory and performance](https://lwn.net/Articles/255364/).

Specifically, we look at how the order of memory access impacts performance. The example code will perform an initialisation of
and a read from a 5000x5000 matrix. The indexes will be varied
such that these operations are performed each row at a time
(sequential memory accesses), and then each column at a time (
non sequential memory access).

The code for these operations:

```C
#define M_SIZE 5000

void populate_matrix(double matrix[M_SIZE][M_SIZE]) {
    double elem = 1.0;
    for (int i = 0; i < M_SIZE; i++) {
        for (int j = 0; j < M_SIZE; j++) {
            matrix[i][j] = elem;
        }
    }
}

double read_matrix(double matrix[M_SIZE][M_SIZE]) {
    double sum = 0.0;
    for (int i = 0; i < M_SIZE; i++) {
        for (int j = 0; j < M_SIZE; j++) {
            sum += matrix[i][j];
        }
    }
    return sum;
}
```

These were timed with the `TIME_FUNC` macro from the measurement
section. The code shows the case for sequential memory access.
For this test, the average timing in microseconds for a few runs were:

```
Populate: 91687 | Read: 70044
```

For the column first, non-sequential memory access test (swapping
the `i` and `j` indicies when writing/accessing elements in the
above code):

```
Populate: 146648 | Read: 103563
```

As expected, the sequential operations are quite a bit faster.
In this simple example, it is easy to see how sequential data
accesses can be done, however it's not always this obvious
and may require other code or algorithm modifications.
Ulrich goes into an example of how matrix multiplications also
suffers from this non-sequential data access in the naive
implementation, and how algorithm modification to using the 
transpose of a matrix helps alleviate it (read the LWN article!).

Just for fun, an AVX-512 implementation was made for the matrix
write/reads:

```C
void populate_matrix_avx(double matrix[M_SIZE][M_SIZE]) {
    __m512d elem_vec = _mm512_set1_pd(1.0);
    for (int i = 0; i < M_SIZE; i+= 8) {
        for (int j = 0; j < M_SIZE; j+=8) {
            _mm512_store_pd(&matrix[i][j], elem_vec);
        }
    }
}

double read_matrix_avx(double matrix[M_SIZE][M_SIZE]) {
    double sum = 0.0;
    __m512d sum_vec = _mm512_setzero_pd();
    __m512d elem_vec;
    for (int i = 0; i < M_SIZE; i+= 8) {
        for (int j = 0; j < M_SIZE; j+=8) {
            elem_vec = _mm512_load_pd(&matrix[i][j]);
            sum_vec = _mm512_add_pd(sum_vec, elem_vec);
        }
    }

    sum = _mm512_reduce_add_pd(sum_vec);
    return sum;
}
```

Note the AVX-512 load/stores required the matrix be allocated on
a 64-byte boundary (such as with `aligned_alloc(3)`). No
considerations had to be made for any elements at the end of
rows since the matrix size was divisible by the vector size.

The average results of performing sequential accesses were:

```
Populate: 11527 | Read: 3587
```

With non-sequential access:

```
Populate: 17163 | Read: 6869
```

These suffered a percentage slowdown with non-sequential access
in around the same ballpark as the non-AVX code, with the
non-sequential read operation suffering slightly more (although
note, the variance in the results was quite large and so
probably should be taken with a grain of salt).

<hr>

### Results Summary

This section records the results for the various tests performed. The speed
comparison compares run times to the base case with no optimisations
(lower number is faster).

In the tables below, `Riemann Time` is the `bpftrace` measured time of the
`integral_riemann` function measured in microseconds, and `Speed Comparison`
is the `Riemann Time` of the test case over the base case. The `Instructions`
column measures the amount of instructions executed as measured by `perf stat`.

The `Taylor series -O3 -mavx` test compiles with `-mavx` only without
manual vectorisation, while `Taylor series -O3 vector` performs vectorisation
of the Taylor series functions.

For the `f_simple` tests:

| Optimisation | Riemann Time | Speed Comparison | Instructions |
| ------------ | ------------ | ---------------- | ------------ |
| Base case    |  6847828     | 1.000            | 94,076,906,095 |
| gcc -O3      |  6454392     | 0.943            | 83,095,613,744 |
| Hot loop rewrite | 6764517  | 0.988            | 91,097,777,304 |
| Small angle  | 5343617      | 0.780            | 77,191,972,384 |
| Small angle positive case | 5080937 | 0.742    | 71,366,823,827 |
| Small angle `likely()` | 5012777 | 0.732       | 73,416,966,946 |
| Taylor series -O3 | 3701438 | 0.541            | 41,046,867,512 |
| Taylor series -O3 -mavx | 3694076 | 0.539      | 36,035,029,568 |
| Taylor series -O3 vector | 412555 | 0.060      | 3,376,218,778  |

For the `f_intermediate` tests:

| Optimisation | Riemann Time | Speed Comparison | Instructions |
| ------------ | ------------ | -----------------| ------------ |
| Base case    |  14846748    | 1.000            | 235,111,065,770 |
| gcc -O3      |  13707645    | 0.923            | 228,149,636,174 |
| gcc -O3 -ffast-math | 8466576  | 0.570         | 151,045,821,625 |
| Hot loop rewrite | 14184865 | 0.955            | 226,124,658,709 |
| Small angle  | 14392529     | 0.969            | 218,235,603,025 |
| Small angle positive case | 14154213 | 0.953   | 212,453,637,442 |
| Small angle `likely()` | 14004255 | 0.943      | 214,465,059,223 |
| Taylor series -O3 | 9660417 | 0.651            | 237,080,118,269 |
| Taylor series -O3 -mavx | 8420865 | 0.567      | 128,107,924,611 |
| Taylor series -O3 vector | 552366 | 0.037      | 4,753,831,520   |

<hr>

### Conclusions

This exploration into performance techniques barely stratched
the surface of performance engineering, but it does start to give some intuition
into the sort of considerations that might be made when optimising software
Even more importantly, it has resulted in the collection of many helpful
references.

It should be noted that the test code that was examined did not cover many
concepts that are very relevant to performance, such as file I/O and
network operations. These are saved for future explorations (and to avoid
dragging out an already long winded series).

Next, we look at some parallel programming methods.

<br>

[Introduction](introduction.html)
<p style="text-align: right">
[Multicore Optimisations](optimisation-multicore.html)
</p>
