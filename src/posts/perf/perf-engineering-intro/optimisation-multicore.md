---
title: Multicore Optimisations
author: Seb
author-url: /
date: 2024-11-25
lang: en
toc-title: Contents
version: v1.0.0
---

### Introduction

This section follows up from the previous, except it looks at multicore technqiues.
Although the title alludes to multicore optimisations, really this section
just explores a few different ways of doing parallel programming.

Some methods explored include:

- Classic Linux pthreads
- Using OpenMP to get a feel for commonly used HPC programming method
- Using NVIDIA's CUDA to explore programming GPUs
- Using OpenCL as an alternative for GPU programming

<hr>

### Base Case

The base case results are copied over from the single core section for 
more convenient comparison.

#### Measurement - Simple

`perf stat`:

```
 Performance counter stats for '../simple-main.out' (5 runs):

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

### Linux pthreads

The test code provides an ideal environment for doing parallel computing-
no data sharing or locks are required, each execution unit can just execute
a function with a slice of work assigned to it. In this case, the slice of work
is a smaller region within the upper and lower bounds of a Riemann integral.

One of the most basic ways to do this parallelisation is with pthreads created by `pthread_create()`.

The summary of the modifications that need to be made to the test code is that
each thread needs to be provided with a context of what work to do, as well as a
place to store its results.


The `integral_riemann()` function was turned into a thread initialiser and
runner, and a new `integral_riemann_thread()` function was created to perform
the actual integral summation, given a chunk of work. 

Another thing the code does is sets the affinity of a thread to a specific CPU
core. This binds the thread to only run on that CPU, which has benefits related to
caching since a given slice of work will only be worked on by a single physical
thread. The benefits probably won't be seen for the toy sample code, but it's a
concept worth keeping in mind for more complex cases.

```C
// Context provided to a single thread that describes the work it should do
struct riemann_sum_ctx {
    double lower_bound;
    double upper_bound;
    double step;
    mathfunc_single_param_t integrand_f;
    double *sum_accum;
};


// Thread target
// arg is interpreted as a `struct riemann_sum_ctx`
void *integral_riemann_thread(void *arg) {
    struct riemann_sum_ctx *ctx = (struct riemann_sum_ctx *)arg;
    double sum = 0.0;
    for (double n = ctx->lower_bound; n < ctx->upper_bound; n += ctx->step) {
        // The multiplication is kept here for fairer comparison with the base case
        sum += (ctx->integrand_f(n) * ctx->step);
    }

    // Store the acquired result in the provided location
    *(ctx->sum_accum) = sum;

    return NULL;
}

double __attribute__ ((noinline)) integral_riemann(mathfunc_single_param_t integrand,
        double upper_bound, double lower_bound, double split, int nthreads) {

    // Bounds checks are ignored
    double step = (upper_bound - lower_bound) / split;

    // The block of rectangles to assign to a single thread
    double nthread_split = (split / nthreads);

    // Array accumulating the results from various threads
    double *sum_accum = calloc(nthreads, sizeof(double));

    pthread_t *all_threads = calloc(nthreads, sizeof(pthread_t));
    struct riemann_sum_ctx *all_ctx = calloc(nthreads,
            sizeof(struct riemann_sum_ctx));

    double cur_lower_bound = lower_bound;
    double cur_upper_bound = lower_bound + (step * nthread_split);
    pthread_attr_t cur_attr;
    cpu_set_t cur_cpu_set;

    // Start all threads, providing a context with the bounds to calculate,
    // integrand function to use, and a storage space for the results;
    for (int i = 0; i < nthreads; i++) {
        struct riemann_sum_ctx *cur_ctx = &all_ctx[i]; //calloc(1, sizeof(struct riemann_sum_ctx));
        cur_ctx->lower_bound = cur_lower_bound;
        cur_ctx->upper_bound = cur_upper_bound;
        cur_ctx->step = step;
        cur_ctx->integrand_f = integrand;
        cur_ctx->sum_accum = &sum_accum[i];

        // Set thread affinity to a single CPU. Assume that nthreads <= num CPUs
        // Errors ignored for brevity
        pthread_attr_init(&cur_attr);
        CPU_ZERO(&cur_cpu_set);
        CPU_SET(i, &cur_cpu_set);
        pthread_attr_setaffinity_np(&cur_attr, sizeof(cpu_set_t), &cur_cpu_set);

        pthread_create(&all_threads[i], &cur_attr, integral_riemann_thread, cur_ctx);
        // Update bounds for next run
        cur_lower_bound = cur_upper_bound;
        cur_upper_bound += (step * nthread_split);

        // Has no effect on threads that used this attribute struct
        pthread_attr_destroy(&cur_attr);
    }

    // Wait for all threads to run, add their results
    double sum = 0.0;
    for (int i = 0; i < nthreads; i++) {
        pthread_join(all_threads[i], NULL);
        sum += sum_accum[i];
    }
    free(all_threads);
    free(all_ctx);
    free(sum_accum);
    return sum;
}
```

#### Measurement - Simple

Sanity check: results seem accurate

```
Riemann:	0.707107
Analytical:	0.707107
```

`perf stat`

```
 Performance counter stats for './test.out' (5 runs):

         11,011.56 msec task-clock:u                     #   15.526 CPUs utilized               ( +-  0.68% )
                 0      context-switches:u               #    0.000 /sec                 
                 0      cpu-migrations:u                 #    0.000 /sec                 
               107      page-faults:u                    #    9.717 /sec                        ( +-  0.96% )
    44,229,816,368      cycles:u                         #    4.017 GHz                         ( +-  0.21% )  (71.38%)
       349,020,061      stalled-cycles-frontend:u        #    0.79% frontend cycles idle        ( +-  4.75% )  (71.33%)
    94,957,685,418      instructions:u                   #    2.15  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.02% )  (71.41%)
    10,992,954,578      branches:u                       #  998.310 M/sec                       ( +-  0.01% )  (71.47%)
            38,107      branch-misses:u                  #    0.00% of all branches             ( +-  0.69% )  (71.50%)
    33,917,664,527      L1-dcache-loads:u                #    3.080 G/sec                       ( +-  0.11% )  (71.53%)
            84,741      L1-dcache-load-misses:u          #    0.00% of all L1-dcache accesses   ( +-  4.79% )  (71.50%)
   <not supported>      LLC-loads:u                                                      
   <not supported>      LLC-load-misses:u                                                

           0.70925 +- 0.00605 seconds time elapsed  ( +-  0.85% )
```

`perf report`

```
Samples: 575K of event 'cycles:P', Event count (approx.): 43328118163
Overhead  Command          Shared Object           Symbol
  61.26%  simple-main-thr  libm.so.6               [.] __cos_fma
  23.20%  simple-main-thr  simple-main-thread.out  [.] integral_riemann_thread
  13.54%  simple-main-thr  simple-main-thread.out  [.] f_simple
   1.64%  simple-main-thr  simple-main-thread.out  [.] cos@plt
```

`bpftrace`

```
Microseconds in Riemann integral: 725375
```

Compared to the base case, there appears to be fewer L1-dcache misses (although
there was quite a lot of variance in this value over multiple runs).

#### Measurement - Intermediate

Accuracy is still good for the intermediate function:

```
Riemann:	0.442619
Analytical:	0.442619
```

`perf stat`

```
 Performance counter stats for './intermediate-main-thread.out' (5 runs):

         28,628.92 msec task-clock:u                     #   15.814 CPUs utilized               ( +-  3.19% )
                 0      context-switches:u               #    0.000 /sec                 
                 0      cpu-migrations:u                 #    0.000 /sec                 
               106      page-faults:u                    #    3.703 /sec                        ( +-  0.69% )
   111,708,146,425      cycles:u                         #    3.902 GHz                         ( +-  0.04% )  (71.43%)
       280,483,146      stalled-cycles-frontend:u        #    0.25% frontend cycles idle        ( +- 11.81% )  (71.41%)
   235,918,164,377      instructions:u                   #    2.11  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.01% )  (71.42%)
    23,992,618,217      branches:u                       #  838.055 M/sec                       ( +-  0.01% )  (71.43%)
           107,570      branch-misses:u                  #    0.00% of all branches             ( +-  2.93% )  (71.44%)
    75,791,358,148      L1-dcache-loads:u                #    2.647 G/sec                       ( +-  0.05% )  (71.46%)
           203,534      L1-dcache-load-misses:u          #    0.00% of all L1-dcache accesses   ( +-  2.62% )  (71.45%)
   <not supported>      LLC-loads:u                                                      
   <not supported>      LLC-load-misses:u                                                

            1.8104 +- 0.0590 seconds time elapsed  ( +-  3.26% )
```

`perf report`

```
Samples: 1M of event 'cycles:P', Event count (approx.): 111497598005
Overhead  Command          Shared Object                 Symbol
  47.76%  intermediate-ma  libm.so.6                     [.] __ieee754_pow_fma
  22.75%  intermediate-ma  libm.so.6                     [.] __cos_fma
  10.69%  intermediate-ma  libm.so.6                     [.] pow@@GLIBC_2.29
   8.76%  intermediate-ma  intermediate-main-thread.out  [.] f_intermediate
   7.58%  intermediate-ma  intermediate-main-thread.out  [.] integral_riemann_thread
```

`bpftrace`

```
Microseconds in Riemann integral: 1869606
```

<hr>

### Linux pthreads + AVX

For fun, let's see what sort of numbers can be achieved using AVX along with
pthreads. The vectorised Taylor series code from the singlecore section was used,
and the vectorised `integral_riemann` function was simply moved to inside
`integral_riemann_thread`.

#### Measurement - Simple

`perf stat`

```
 Performance counter stats for './simple-main-thread-vector.out' (5 runs):

            920.44 msec task-clock                       #   15.158 CPUs utilized               ( +-  0.52% )
                51      context-switches                 #   55.408 /sec                        ( +-  4.41% )
                16      cpu-migrations                   #   17.383 /sec                        ( +-  3.06% )
               112      page-faults                      #  121.681 /sec                        ( +-  0.94% )
     3,682,194,034      cycles                           #    4.000 GHz                         ( +-  0.11% )  (70.48%)
       228,067,080      stalled-cycles-frontend          #    6.19% frontend cycles idle        ( +-  0.27% )  (70.61%)
     3,354,281,579      instructions                     #    0.91  insn per cycle       
                                                  #    0.07  stalled cycles per insn     ( +-  0.13% )  (71.94%)
       375,866,652      branches                         #  408.355 M/sec                       ( +-  0.10% )  (72.11%)
           379,075      branch-misses                    #    0.10% of all branches             ( +-  0.49% )  (72.10%)
     1,757,492,076      L1-dcache-loads                  #    1.909 G/sec                       ( +-  0.11% )  (72.08%)
           338,479      L1-dcache-load-misses            #    0.02% of all L1-dcache accesses   ( +-  7.50% )  (71.74%)
   <not supported>      LLC-loads                                                        
   <not supported>      LLC-load-misses                                                  

          0.060724 +- 0.000141 seconds time elapsed  ( +-  0.23% )
```

`perf report`

```
Samples: 116K of event 'cycles:P', Event count (approx.): 3328719126
Overhead  Command          Shared Object                  Symbol
  55.46%  simple-main-thr  simple-main-thread-vector.out  [.] f_simple
  43.44%  simple-main-thr  simple-main-thread-vector.out  [.] integral_riemann_thread
```

`bpftrace`

```
Microseconds in Riemann integral: 57845
```

Although this is just a toy example, getting code to run in ~0.8% of its
original execution time is fun to see.

#### Measurement - Intermediate

`perf stat`

```
 Performance counter stats for './intermediate-thread-vector.out' (5 runs):

          2,842.16 msec task-clock:u                     #   15.496 CPUs utilized               ( +-  0.11% )
                 0      context-switches:u               #    0.000 /sec                 
                 0      cpu-migrations:u                 #    0.000 /sec                 
               106      page-faults:u                    #   37.296 /sec                        ( +-  0.71% )
    11,629,496,317      cycles:u                         #    4.092 GHz                         ( +-  0.13% )  (71.10%)
     3,733,557,016      stalled-cycles-frontend:u        #   32.10% frontend cycles idle        ( +-  0.47% )  (70.96%)
    27,164,493,119      instructions:u                   #    2.34  insn per cycle       
                                                  #    0.14  stalled cycles per insn     ( +-  0.03% )  (71.14%)
     5,606,533,234      branches:u                       #    1.973 G/sec                       ( +-  0.07% )  (71.58%)
            15,672      branch-misses:u                  #    0.00% of all branches             ( +-  0.85% )  (71.97%)
     2,497,147,630      L1-dcache-loads:u                #  878.609 M/sec                       ( +-  0.09% )  (71.97%)
            15,879      L1-dcache-load-misses:u          #    0.00% of all L1-dcache accesses   ( +-  4.35% )  (71.62%)
   <not supported>      LLC-loads:u                                                      
   <not supported>      LLC-load-misses:u                                                

          0.183415 +- 0.000813 seconds time elapsed  ( +-  0.44% )
```

`perf report`

```
Samples: 160K of event 'cycles:P', Event count (approx.): 12233787299
Overhead  Command          Shared Object                   Symbol
  91.51%  intermediate-th  intermediate-thread-vector.out  [.] f_intermediate
   8.16%  intermediate-th  intermediate-thread-vector.out  [.] integral_riemann_thread
```

`bpftrace`

```
Microseconds in Riemann integral: 182442
```

Interestingly, there is a significant amount of stalled cycles in this test. Even
more interestingly, changing the multiplication order inside `f_intermediate()`
reduces this number slightly and generates a small speedup. The above results
come from a multiplication order of `x * taylor_exp(x) * taylor_cos(x)`.
Changing this to `taylor_exp(x) * taylor_cos(x) * x` results in a runtime of
~`0.168` seconds and a stalled-cycles-frontend value of 20%.

### OpenMP

OpenMP is an API specification for performing multi-threaded, shared
memory parallel programming. This specification is implemented by
[many different compilers](https://www.openmp.org/resources/openmp-compilers-tools/),
including GCC and clang. OpenMP was an interesting case to look at due to its
prevelance in High Performance Computing. For such applications, OpenMP is often
used alongside an MPI implementation such as OpenMPI for distributed memory
message passing. Message passing wasn't needed for the simple test code, and so
was not examined here.

The OpenMP site provides a
[syntax reference guide](https://www.openmp.org/wp-content/uploads/OpenMPRefGuide-5.2-Web-2024.pdf).

The resources used for this section include tutorials from the
[Lawrence Livermore National Laboratory](https://hpc-tutorials.llnl.gov/openmp/)
and the [University of Colorado Boulder](https://curc.readthedocs.io/en/latest/programming/OpenMP-C.html).

The basic case of using OpenMP involves using some `#pragma` directive sections
to define special code regions, such as those that should be executed in
parallel. There are also helper functions to get the number of threads running,
or which thread is currently running some chunk of work.

It was surpisingly straightforward to get something up and running, and only
required modification of the `integral_riemann` function. A
`#pragma omp parallel` region was defined that will automatically be executed by
some number of threads (using the `OMP_NUM_THREADS` environment variable).
The bounds assigned to a particular thread was calculated using its thread number,
and the sums from each thread were brought together in a thread safe
`#pragma omp critical`.

```C
double __attribute__ ((noinline)) integral_riemann(mathfunc_single_param_t integrand, double upper_bound,
        double lower_bound, double split) {
    // Bounds checks are ignored
    double sum = 0.0;
    double partial_sum = 0.0;
    double step = (upper_bound - lower_bound) / split;
    double nthread_split = (split / omp_get_max_threads());

    double thread_lower_bound;
    double thread_upper_bound;

    // Used to calculate the upper and lower bounds for a particular thread
    double thread_chunk_spread = nthread_split * step;

    #pragma omp parallel shared(sum, step, split, nthread_split, thread_chunk_spread)
    {
        double partial_sum = 0.0;
        double thread_lower_bound = thread_chunk_spread * omp_get_thread_num();
        double thread_upper_bound = thread_chunk_spread * (omp_get_thread_num()+1);

        for (double n = thread_lower_bound; n < thread_upper_bound; n += step) {
            partial_sum += (integrand(n) * step);
        }

        // Add up partial sums in a thread safe way
        #pragma omp critical
        {
            sum += partial_sum;
        }
    }

    return sum;
}
```

There were many other OpenMP directives available, so it's possible that the code
could be written in a smarter way, however even in it's current state it required
less work than using pthreads (makes sense given that it's a higher level
construct).

#### Measurement - Simple

Sanity check: accuracy is good

```
Riemann:	0.707107
Analytical:	0.707107
```

`perf stat`

```
 Performance counter stats for './simple-main-openmp.out' (5 runs):

         11,284.30 msec task-clock                       #   15.654 CPUs utilized               ( +-  0.06% )
               447      context-switches                 #   39.613 /sec                        ( +-  5.50% )
                 0      cpu-migrations                   #    0.000 /sec                 
               133      page-faults                      #   11.786 /sec                        ( +-  1.17% )
    46,451,441,275      cycles                           #    4.116 GHz                         ( +-  0.03% )  (71.43%)
       105,540,697      stalled-cycles-frontend          #    0.23% frontend cycles idle        ( +-  1.82% )  (71.39%)
    95,125,136,441      instructions                     #    2.05  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.01% )  (71.41%)
    12,030,432,212      branches                         #    1.066 G/sec                       ( +-  0.02% )  (71.45%)
         2,756,249      branch-misses                    #    0.02% of all branches             ( +-  0.94% )  (71.45%)
    31,046,661,926      L1-dcache-loads                  #    2.751 G/sec                       ( +-  0.02% )  (71.49%)
         2,621,403      L1-dcache-load-misses            #    0.01% of all L1-dcache accesses   ( +-  1.00% )  (71.50%)
   <not supported>      LLC-loads                                                        
   <not supported>      LLC-load-misses                                                  

           0.72086 +- 0.00281 seconds time elapsed  ( +-  0.39% )
```

`perf report`

```
Samples: 605K of event 'cycles:P', Event count (approx.): 46219698949
Overhead  Command          Shared Object           Symbol
  61.28%  simple-main-ope  libm.so.6               [.] __cos_fma
  24.07%  simple-main-ope  simple-main-openmp.out  [.] integral_riemann._omp_fn.0
  11.50%  simple-main-ope  simple-main-openmp.out  [.] f_simple
   2.15%  simple-main-ope  simple-main-openmp.out  [.] cos@plt
```

`bpftrace`

```
Microseconds in Riemann integral: 742329
```

Results were fairly comparable to the pthreads case here, if slightly slower.

#### Measurement - Intermediate

`perf stat`

```
 Performance counter stats for './intermediate-main-openmp.out' (5 runs):

         28,983.99 msec task-clock                       #   15.473 CPUs utilized               ( +-  3.04% )
               996      context-switches                 #   34.364 /sec                        ( +- 11.90% )
                 9      cpu-migrations                   #    0.311 /sec                        ( +- 82.82% )
               139      page-faults                      #    4.796 /sec                        ( +-  1.48% )
   113,759,251,278      cycles                           #    3.925 GHz                         ( +-  0.05% )  (71.42%)
       374,681,343      stalled-cycles-frontend          #    0.33% frontend cycles idle        ( +-  6.62% )  (71.40%)
   236,237,309,751      instructions                     #    2.08  insn per cycle       
                                                  #    0.00  stalled cycles per insn     ( +-  0.01% )  (71.41%)
    25,059,856,298      branches                         #  864.610 M/sec                       ( +-  0.01% )  (71.44%)
         6,914,352      branch-misses                    #    0.03% of all branches             ( +-  3.29% )  (71.45%)
    73,563,201,411      L1-dcache-loads                  #    2.538 G/sec                       ( +-  0.08% )  (71.46%)
        23,518,921      L1-dcache-load-misses            #    0.03% of all L1-dcache accesses   ( +- 72.64% )  (71.45%)
   <not supported>      LLC-loads                                                        
   <not supported>      LLC-load-misses                                                  

            1.8732 +- 0.0826 seconds time elapsed  ( +-  4.41% )
```

`perf report`

```
Samples: 1M of event 'cycles:P', Event count (approx.): 112835682962
Overhead  Command          Shared Object                 Symbol
  44.96%  intermediate-ma  libm.so.6                     [.] __ieee754_pow_fma
  24.34%  intermediate-ma  libm.so.6                     [.] __cos_fma
  10.33%  intermediate-ma  libm.so.6                     [.] pow@@GLIBC_2.29
   9.62%  intermediate-ma  intermediate-main-openmp.out  [.] f_intermediate
   8.01%  intermediate-ma  intermediate-main-openmp.out  [.] integral_riemann._omp_fn.0
```

`bpftrace`

```
Microseconds in Riemann integral: 1928942
```

Same commentary as before- more or less the same as the pthreads case, maybe
slightly slower.

#### OpenMP Vectorised Notes

A similar test to the pthreads example was ran, where the vectorised versions of
functions were used with the OpenMP code. This produced more or less the exact
same results as the pthreads versions with the same notes, so these results
are not included.

<hr>

### GPU - CUDA

Next we look at some GPU programming with NVIDIA's CUDA programming interface/toolkit.

The resources using include NVIDIA's [introductory guide to CUDA](https://developer.nvidia.com/blog/even-easier-introduction-cuda/). The
[CUDA C++ Programming Guide](https://docs.nvidia.com/cuda/cuda-c-programming-guide/)
was also used.

#### Introduction

The main difference between GPU and CPU execution is that CPUs are designed to
run a single thread per core (or more, with technologies like Simulataneous
Multithreading) very fast. The total number of threads that can run
simultaneously is fairly low (16 on my system), at least by comparison with GPUs.

GPUs run thousands of threads in parallel, each at a lower speed than CPUs. This
makes them suited for highly parallel data processing tasks.


CUDA allows definitions of functions called kernels that are to be executed on
a GPU. These are defined using the `__global__` declaration. When calling the
kernels, a `<<<stuff>>>` syntax is used to specify how many blocks/threads will
be used when executing that kernel.

Thread blocks can be specified in 1/2/3 dimensions to provide more natural ways
to specify computations related to vectors/matricies/volumes. The example code
is translated to a 1 dimensional thread block for clarity. Each thread block
can have a maximum of 1024 threads on my device (NVIDIA GeFore RTX 3080). There are a few factors to
consider when determining how many blocks to use/threads per block, including
GPU shared memory and register limitations per multiprocessor. A
[stack overflow post](https://stackoverflow.com/questions/4391162/cuda-determining-threads-per-block-blocks-per-grid)
gave some beginner advice on the topic. NVIDIA also has some
[tables that list the various technical details for its devices](https://docs.nvidia.com/cuda/cuda-c-programming-guide/#features-and-technical-specifications).
Blocks themselves are organised into a 'grid'.

NVIDIA has a [repo of code examples](https://github.com/NVIDIA/cuda-samples/tree/master),
including for a [`deviceQuery`](https://github.com/NVIDIA/cuda-samples/blob/master/Samples/1_Utilities/deviceQuery/deviceQuery.cpp)
application. The stats of threads/block and number of multiprocessors on the device
were found using this application. This was used to find that my device had
68 multiprocessors available.

<br>

#### Example Kernel

An kernel was made to demonstrate how work can be distributed amongst threads.
In this example, a number is given to a thread and the thread calculates
how to split the number, and what chunk of work it would be assigned to do.

These values are obtained from built-in variables that are accessible within
a kernel, such as `gridDim` `blockDim`, `blockIdx`, and `threadIdx`. These
variables have 3 dimensions, which can be accessed via its `.x`, `.y`, and `.z`
members. In the example below it's assumed these are 1 dimensional, so only
the `.x` member is used.

```C
__global__
void divide_work_even_split(int number) {
    int stride = blockDim.x * gridDim.x
    int assigned = blockIdx.x * blockDim.x + threadIdx.x;
    // Assumes a whole number division
    int split = number / stride;
    int assigned_split = assigned * split;

    printf("threadIdx: %d | blockIdx: %d\n", threadIdx.x, blockIdx.x);
    printf("Stride: %d | Assigned: %d\n", stride, assigned);
    printf("Split: %d | Assigned split: %d\n", split, assigned_split);
}
```

Invoking this kernel with 1 block and 2 threads/block to split up the value
`100` can be done with:

```C
divide_work_even_split<<<1, 2>>>(100);
```

This can be placed within a `test_cuda.cu` file (which is just a C++ file) inside
the `main()` function and compiled with the `nvcc` compiler. The function call
will be ran by 2 different threads, yielding the output:

```
threadIdx: 0 | blockIdx: 0
threadIdx: 1 | blockIdx: 0
Stride: 2 | Assigned: 0
Stride: 2 | Assigned: 1
Split: 50 | Assigned split: 0
Split: 50 | Assigned split: 50
```

Changing the values to 2 blocks each with 2 threads results in the output:

```
threadIdx: 0 | blockIdx: 0
threadIdx: 1 | blockIdx: 0
threadIdx: 0 | blockIdx: 1
threadIdx: 1 | blockIdx: 1
Stride: 4 | Assigned: 0
Stride: 4 | Assigned: 1
Stride: 4 | Assigned: 2
Stride: 4 | Assigned: 3
Split: 25 | Assigned split: 0
Split: 25 | Assigned split: 25
Split: 25 | Assigned split: 50
Split: 25 | Assigned split: 75
```

In this way it's easy to see how an individual thread can calculate what
work it should do.

<br>

#### Test Code

Translating the test code to a CUDA kernel was fairly straightforward. A
section was added for the running thread to calculate the chunk of work assigned
to it in a similar way to the previous section. Afterwards, the same Riemann
sum loop was ran over the calculated bounds, except without the previously used
function pointers.

The `f_simple()` and `f_intermediate()` functions had to be
designated with the `__device__` declaration, marking them as functions to run
on the GPU. This new intergral kernel is `integral_riemann_kernel()` in the code
below. It is invoked in `integral_riemann_kernel()`, which serves to set up
some state (including the number of blocks/threads to use) and run the kernel.

Each kernel writes its result to a buffer allocated to be accessible from both GPU and CPU space. After the kernels are finished, this buffer is summed over to get the
final result.


The [NVIDIA docs](https://docs.nvidia.com/cuda/cuda-c-programming-guide/index.html#function-pointers)
specify that it is not allowed to take the address of a `__device__` function in
host code, which seems to make it hard to do the same function pointer passing
from the regular test code. There [are posts](https://leimao.github.io/blog/Pass-Function-Pointers-to-Kernels-CUDA/)
on doing function pointer things using templates and memcpy operations, and
NVIDIA provides some [sample code that uses function pointers](https://github.com/NVIDIA/cuda-samples/tree/master/Samples/2_Concepts_and_Techniques/FunctionPointers),
however for the testing the function that was called was manually modified from
`f_simple` to `f_intermediate`.


```C
__global__
void integral_riemann_kernel(double upper_bound, double lower_bound,
    double split, double *results) {

  // Split assigned chunks over the number of threads
  long thread_chunks = blockDim.x * gridDim.x;
  long assigned_thread_chunk = blockIdx.x * blockDim.x + threadIdx.x;

  // Split the number of rectangles evenly over the number of threads
  double work_per_thread = split / thread_chunks;
  double assigned_chunk_start = assigned_thread_chunk * work_per_thread;

  // Bounds checks are ignored
  double step = (upper_bound - lower_bound) / split;

  double thread_lower_bound = assigned_chunk_start * step;
  double thread_upper_bound = (assigned_chunk_start + work_per_thread) * step;

  double sum = 0.0;
  for (double n = thread_lower_bound; n < thread_upper_bound; n += step) {
        sum += f_simple(n) * step;
        //sum += (f_intermediate(n) * step);
  }
  results[assigned_thread_chunk] = sum;
}

double integral_riemann(mathfunc_single_param_t integrand, double upper_bound,
        double lower_bound, double split) {
    
    int numBlocks = 68;
    int blockSize = 1024;
    int totalThreads = numBlocks * blockSize;
    // Allocate memory to hold sums for each thread
    // This is accessible from both CPU and GPU memory
    // Errors ignored for brevity
    double *all_sums;
    cudaMallocManaged(&all_sums, totalThreads*sizeof(double));

    integral_riemann_kernel<<<numBlocks, blockSize>>>(upper_bound, lower_bound,
                                                      split, all_sums);

    // Wait for GPU to finish
    cudaDeviceSynchronize();

    double sum = 0.0;
    for (int i = 0; i < totalThreads; i++) {
        sum += all_sums[i];
    }
    cudaFree(all_sums);
    return sum;
}
```

The maximum number of threads per block was used (1024), and the number of blocks
was set to the number of multiprocessors on the GPU (68).

<br>

#### Base Case - Windows

The GPU system I had was running Windows, so to get some fairer comparisons the
base case the test code was copied over to the Windows system and built.

Trying to find/use performance related tools on Windows was not fun and is not
recommended. In the end the diagnostic tools that come with Visual Studio were
used to observe how fast the 'Release' version of the built code ran. I'm not
entirely sure what optimisations the 'Release' version might add, but a very
primal feeling of fear told me to get off this platform as fast as possible.

Collecting extra information like the number of instructions executed/cycles taken
or cache miss rates is left as an exercise to the user.

The CPU used is a Intel Core i7-12700KF.

The `f_simple` case ran in `1.568` seconds.

The `f_intermediate` case ran in `14.589` seconds, which didn't make much sense
given the `f_simple` test, but questioning it quickly became out of scope the
longer I spent in this environment.

#### Measurement - Simple

The number of rectangles were not split perfectly among the 68 blocks of 1024 threads (69632 threads total), so the accuracy of the results suffered a bit:

```
Riemann:	0.707146
Analytical:	0.707107
```

The `NVIDIA Nsight Systems` application was used to perform GPU kernel profiling,
and reported that the `integreal_riemann_kernel` function
took `~95ms` to run. Bumping the split number to 10 billion resulted in a `~888ms` run. These results were for the case of using the regular math functions
(`cos()`), which are provided by built-in functions accessible to the kernels.

When using the Taylor series functions instead this number went up to
`460ms` (back at a 1 billion rectangle split). It appears that the compiler
did not make the same sort of optimisations that GCC did to these functions.

Using the `cosine_approx()` small angle approximation code resulted in slightly
worse performance than the original run at `113ms`.

This was a somewhat surprising result for a few reasons. It was expected that this method would result in the fastest execution (although it _was_ the fastest when not considering AVX code). It is very possible that I was unaware of some CUDA
features available that would've improved these results, or could've structured
the code to take advantage of the hardware better.

It may also be the case that the toy code example was easier for the compiler to
optimise to run on a CPU, and the benefits may not scale to more complex cases.

It is also surprising to see that some of the optimisations that made CPU code
faster (small angle approximations, Taylor expansions) did not achieve speedups
for the GPU code- perhaps this had to do with the operations being performed,
or perhaps the translation to GPU code did not result in the same sort of
optimisations being performed that were done to the CPU code.

#### Measurement - Intermediate

Again accuracy was slightly off for the same reasons as the previous case:

```
Riemann:	0.442643
Analytical:	0.442619
```

`NVIDIA Nsight Systems` reported that the `integreal_riemann_kernel` function
took `~458ms` to run using the `math.h` functions.

When using the Taylor series code, this went up to `887ms`.

### OpenCL

OpenCL is an alternative framework to CUDA for running programs on GPUs (and
also on other processing units, e.g. FPGAs). [NVIDIA has support](https://developer.nvidia.com/opencl)
and examples for the OpenCL API.

The main resource used for learning about OpenCL include
[several example problems](https://github.com/rsnemmen/OpenCL-examples) and a
[tutorial from the Univeristy of Luxembourg](https://ulhpc-tutorials.readthedocs.io/en/latest/gpu/opencl/)
on the subject.

OpenCL in general involved a lot more boilerplate than using CUDA, however there
is also more flexibility in the platforms OpenCL programs can run on.

The main parts involved in running an OpenCL program are:

- Creating a context
- Creating a command queue
- Creating a program (and compiling it at runtime)
- Creating a kernel, and operations related to passing it arguments (allocation onto device memory, setting the arguments)
- Enqueuing and running the kernel
- Reading back results from device memory

OpenCL kernels are usually placed in separate files, and like CUDA have access
to some built-in functions related to problem decomposition and some others
(such as math functions).

Two concepts related to running a program are the 'global size' and 'local size'.
The global size represents the entire problem, and dictates how many times a kernel
will be run in total (e.g. the number of pixels to be operated on in an image).
This generally can be as large as required.
The local size dictates how many threads will be created in a group, and is
constrained by the underlying hardware that will run the kernel.
[This stack overflow post described some of the constraints for the different sizes](https://stackoverflow.com/questions/3957125/questions-about-global-and-local-work-size).


#### Code

The kernel to be executed was placed into its own file. The
`integral_riemann_kernel()` function mostly mirrors it's CUDA counterpart, except
it uses OpenCL built-in functions and is directly provided the `split` number
instead of calculating it:

```C

double f_simple(double x) {
    return cos(x);
}

double f_intermediate(double x) {
    return (x * pow(M_E, x) * cos(x));
}

__kernel void integral_riemann_kernel(double split, double step,
    __global double *results) {

    size_t stride = get_local_size(0) * get_num_groups(0);
    size_t assigned_num = get_global_id(0);

    double work_per_thread = split / stride;
    double assigned_start = assigned_num * work_per_thread;

    double thread_lower_bound = assigned_start * step;
    double thread_upper_bound = (assigned_start + work_per_thread) * step;

    double partial_sum = 0.0;
    for (double n = thread_lower_bound; n <= thread_upper_bound; n += step) {
      partial_sum += f_simple(n) * step;
        //partial_sum += f_intermediate(n) * step;
    }
    results[assigned_num] = partial_sum;
}
```

The regular `integral_riemann` function was turned into a kernel initialiser
and runner. The first OpenCL-related part of this function was to determine
the global size to use. Although the global size set for a kernel tends to be
related to the problem being solved, in this case it is set to the number of
threads used in the CUDA code just for an easier time comparing the two
implementations/results. This means the individual kernel threads will figure
out which block of the 1 billion rectangles they should be handling, similar to
the CUDA case.

This global size is also used to allocate a results array to eventually read back
the partial sums of every thread.

```C
size_t globalSize = 68 * 1024;
size_t localSize = 1024;
double *sum_accum = calloc(globalSize, sizeof(double));
size_t sum_accum_sz = globalSize * sizeof(double);

// Device memory for the sum accumulation buffer
cl_mem sum_accum_kernel;
```

Then, the platform and device is selected. Error checking is ignored for brevity.

```C
cl_int err;
cl_platform_id platform_id;
cl_device_id device_id;
err = clGetPlatformIDs(1, &platform_id, NULL);
err = clGetDeviceIDs(platform_id, CL_DEVICE_TYPE_GPU, 1, &device_id, NULL);
```

This is followed by setting up the context and command queue. Note that OpenCL
comes with some APIs for performing profiling, which is set in the command queue
creation here.

```C
cl_context context = clCreateContext(0, 1, &device_id, NULL, NULL, &err);
cl_command_queue queue = clCreateCommandQueue(context, device_id,  CL_QUEUE_PROFILING_ENABLE, &err);
```

Next the program is built and the kernel is set up:

```C
cl_program program = build_program(context, device_id, PROGRAM_FILE);
cl_kernel kernel = clCreateKernel(program, "integral_riemann_kernel", &err);
```

`PROGRAM_FILE` is simply the name of the source file containing the kernel, and
the `build_program` function here contains some functionality to read a source
file into memory, then calls the following OpenCL functions:

```C
program = clCreateProgramWithSource(ctx, 1,
(const char**)&program_buffer, &program_size, &err);
err = clBuildProgram(program, 0, NULL, NULL, NULL, NULL);
```

Next, a results buffer is allocated in device memory and the kernel arguments
are set:

```C
sum_accum_kernel = clCreateBuffer(context, CL_MEM_WRITE_ONLY, sum_accum_sz, NULL, NULL);

// Set kernel arguments
err = clSetKernelArg(kernel, 0, sizeof(double), &split);
err |= clSetKernelArg(kernel, 1, sizeof(double), &step);
err |= clSetKernelArg(kernel, 2, sizeof(cl_mem), &sum_accum_kernel);
```

Afterwards, the kernel is ran and waited for. The `event0` variable is used
to collect profiling data, which was set earlier during command queue creation.

```C
cl_event event0;
err = clEnqueueNDRangeKernel(queue, kernel, 1, NULL, &globalSize, &localSize,
                  0, NULL, &event0);
clWaitForEvents (1, &event0);
clFinish(queue);
```

The profiling data is read afterwards:

```C
unsigned long start = 0;
unsigned long end = 0;
clGetEventProfilingInfo(event0,CL_PROFILING_COMMAND_START,
sizeof(cl_ulong),&start,NULL);
clGetEventProfilingInfo(event0,CL_PROFILING_COMMAND_END,
sizeof(cl_ulong),&end,NULL);

// Compute the duration in nanoseconds, then convert to microseconds
unsigned long duration = end - start;
printf("Microseconds taken: %g\n", ((double)duration)/1e3);
```

The partial sums are then read into the `sum_accum` buffer, which is also waited
for:

```C
clEnqueueReadBuffer(queue, sum_accum_kernel, CL_TRUE, 0,
          sum_accum_sz, sum_accum, 0, NULL, NULL);

clFinish(queue);
```

Finally, the final result is tallied and returned:

```C
clFinish(queue);
double sum = 0.0;
for (int i = 0; i < globalSize; i++) {
  sum += sum_accum[i];
}
return sum;
```

This code was compiled and ran on both the previous NVIDIA RTX 3080 and also
a Radeon 780M integrated graphics processor, found on a AMD Ryzen 7840U.

Similarly to the CUDA measurement, the profiling data for the kernel run time
is used only, instead of the runtime for the whole program.

#### Measurement 780M - Simple

The accuracy was slightly off, in the same way as the CUDA case and for
the same reasons:

```
Riemann:	0.707146
Analytical:	0.707107
```


The average runtime was:

```
Microseconds taken: 752414
```

This was not bad, and about matched the OpenMP test. Note that this time is
measured for the kernel only, _not_ the `integral_riemann` function, which is
what most of the other tests measured. They are spiritually equivalent, however
not entirely comparable. The `integral_riemann` function in this case takes
about ~`1004732` microseconds to run (includes the run time for the kernel),
which shows the impact of some of the OpenCL setup code.

It was interesting to see what sort of computation capability an integrated
graphics processor had.

Using the Taylor expansions resulted in worse performance, with runtimes
~`1138400` microseconds.

Using the cosine small angle approximation resulted in a faster runtime of
~`455588` microseconds (but with different result errors).

#### Measurement 780M - Intermediate

Again, the accuracy was off in the same way as the CUDA case:

```
Riemann:	0.442643
Analytical:	0.442619
```

The average runtime was:

```
Microseconds taken: 1180752
```

This was fairly surprising- the result was faster than the OpenMP/pthreads case!

The Taylor expansion code was slower, resulting in average runtimes
of ~`1795730` microseconds.

#### Measurement RTX 3080 - Simple

The accuracy was the same as the previous and CUDA cases.

The average runtime was:

```
Microseconds taken: 94081
```

This was roughly the same as the CUDA case- there may be some small differences in
how the profiling data is obtained here vs. how NVIDIA Nsight obtains it.
In any case, there doesn't seem to be additional overhead involved with using
the OpenCL API instead of CUDA.

When using the Taylor expansion code, this time went up to ~`457113` microseconds-
again the same as the CUDA example. This trend of following the CUDA case
continued for the small angle approximation, which ran in ~`112933` microseconds.

#### Measurement RTX 3080 - Intermediate

The accuracy has the same notes as the previous test.

The average runtime was:

```
Microseconds taken: 537289
```

This seems to have been slightly slower than the CUDA case.

The Taylor expansion code pushed this up to ~`896687` microseconds, which was
roughly the same as the CUDA case.

### Summary

In the tables below, `Riemann Time` is the `bpftrace` measured time of the
`integral_riemann` function measured in microseconds, and `Speed Comparison`
is the `Riemann Time` of the test case over the base case. The `Instructions`
column measures the amount of instructions executed as measured by `perf stat`

For the CUDA tests and OpenCL tests, the times measure the time taken to
execute the GPU kernel only, **not** to run the `integral_riemann` function (which is what the other tests measure).
Additionally, the 'Speed Comparison' for the CUDA and OpenCL 3080 tests is measured
against the 'Windows Base case' test instead of the 'Base case'.

The OpenCL 780M integrated graphics processor test is compared against the regular
base case.

For the `f_simple` tests:

| Optimisation | Riemann Time | Speed Comparison | Instructions |
| ------------ | ------------ | ---------------- | ------------ |
| Base case    |  6847828     | 1.000            | 94,076,906,095 |
| Base + pthreads | 725375      | 0.106          | 94,957,685,418 |
| pthreads O3 vectorised | 57845 | 0.008         | 3,354,281,579 |
| OpenMP       | 742329       | 0.108            | 95,125,136,441 |
| Windows Base case | 1568000 | 0.229            | N/A          |
| CUDA         | 95000        | 0.061            | N/A          |
| OpenCL 780M  | 752414       | 0.110            | N/A          |
| OpenCL 3080  | 94081        | 0.060            | N/A          |

For the `f_intermediate` tests:

| Optimisation | Riemann Time | Speed Comparison | Instructions |
| ------------ | ------------ | -----------------| ------------ |
| Base case    |  14846748    | 1.000            | 235,111,065,770 |
| Base + pthreads | 1869606     | 0.126          | 235,918,164,377 |
| pthreads O3 vectorised | 182442 | 0.012        | 27,164,493,119 |
| OpenMP       | 1928942      | 0.130            | 236,237,309,751 |
| Windows Base case | 14589000 | 0.983           | N/A          |
| CUDA         | 458000       | 0.031            | N/A          |
| OpenCL 780M  | 1180752      | 0.080            | N/A          |
| OpenCL 3080  | 537289       | 0.037            | N/A          |

<hr>

### Conclusions

I really need to include more diagrams/graphs and less walls of text.

Overall this was an interesting look into some different parallel programming
techniques that can be used alongside regular CPU programs.

<br>

[Introduction](introduction.html)

<p style="text-align: right">
[Home](/)
</p>
