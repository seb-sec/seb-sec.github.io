---
title: Litanies of Performance
subtitle: (it's a reference page)
author: Seb
author-url: /
date: 2024-11-26
lang: en
toc-title: Contents
version: v1.0.0
---

### Introduction

This is a reference page containing links to various resources
related to software performance. In the past I have found
collections of resources like this very handy, especially when
starting out or investigating something new, so hopefully this
might be helpful to someone too.


### Performance Analysis and Tooling

- https://www.amd.com/en/developer/uprof.html
    - https://docs.amd.com/go/en-US/57368-uProf-user-guide

- https://www.brendangregg.com
    - Contains many helpful pages on software performance methodologies and tooling. Some are linked below
    - https://www.brendangregg.com/linuxperf.html
    - https://www.brendangregg.com/perf.html
    - https://www.brendangregg.com/ebpf.html
    - https://www.brendangregg.com/flamegraphs.html

- https://github.com/bpftrace/bpftrace

- https://www.janestreet.com/performance-engineering/

### General Performance Related Things

- https://www.agner.org/optimize/
    - Another reference sheet for software optimisation topics
    - Includes guides for C++/assembly optimisation

- https://people.freebsd.org/~lstewart/articles/cpumemory.pdf
    - The classic Ulrich Drepper paper

- https://lwn.net/Articles/255364/
    - Part of Ulrich Drepper's paper, specifically concerning things like memory access order and struct layouts (with `Pahole` usage examples)

- https://fgiesen.wordpress.com
    - Blog with lots of good posts. Some pages with additional references are linked below
    - https://fgiesen.wordpress.com/2013/02/17/optimizing-sw-occlusion-culling-index/
    - https://fgiesen.wordpress.com/category/papers/

- https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/tuning-guides/58479_amd-epyc-9005-tg-hpc.pdf

- https://www.intel.com/content/www/us/en/content-details/671488/intel-64-and-ia-32-architectures-optimization-reference-manual-volume-1.html

### HPC Related Technologies

#### OpenMP

- https://www.openmp.org/wp-content/uploads/omp-hands-on-SC08.pdf
- https://curc.readthedocs.io/en/latest/programming/OpenMP-C.html
- https://hpc-tutorials.llnl.gov/openmp/
- Syntax Reference here https://www.openmp.org/wp-content/uploads/OpenMPRefGuide-5.2-Web-2024.pdf
- Comprehensive code examples for OpenMP features https://www.openmp.org/wp-content/uploads/openmp-examples-4.5.0.pdf

#### OpenMPI

- https://www.open-mpi.org/
- https://mpitutorial.com/tutorials/
- https://docs.open-mpi.org/en/main/index.html

### SIMD

Contains references for related to Single Instruction Multiple
Data instructions/intrinsics.

#### Introductory Resources

https://en.algorithmica.org/hpc/simd/
http://sci.tuomastonteri.fi/programming/sse

#### Libraries

- https://sleef.org/
- https://github.com/vectorclass/version2

#### General

- http://0x80.pl/notesen.html
    - Software blog with many posts of SIMD optimisations/examples

#### References

- https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html
    - Table of intrinsics and their details
- https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html


### GPU Programming - NVIDIA CUDA

#### Introductory Resources

- https://developer.nvidia.com/blog/even-easier-introduction-cuda/
- https://cuda-tutorial.github.io/part1_22.pdf

#### References

- https://docs.nvidia.com/cuda/
    - Has links to several reference pages, some are included below
    - https://docs.nvidia.com/cuda/cuda-c-programming-guide/
    - https://docs.nvidia.com/cuda/cuda-c-best-practices-guide/index.html
    - https://docs.nvidia.com/cuda/cuda-runtime-api/index.html
    - https://docs.nvidia.com/cuda/cuda-math-api/index.html
    - https://docs.nvidia.com/cuda/cublas/index.html

### OpenCL

OpenCL can be used to program a variety of devices, including
GPUs.

#### Introductory Resources

- https://leonardoaraujosantos.gitbook.io/opencl/chapter1
- https://ulhpc-tutorials.readthedocs.io/en/latest/gpu/opencl/
- Hands on introduction to OpenCL https://www.nersc.gov/assets/pubs_presos/MattsonTutorialSC14.pdf


#### References

- https://github.com/rsnemmen/OpenCL-examples
- OpenCL examples by NVIDIA https://developer.nvidia.com/opencl
- https://www.khronos.org/files/opencl30-reference-guide.pdf

<br>

[Home](/)
