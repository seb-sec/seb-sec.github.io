---
title: Litanies of Performance
subtitle: (it's a reference page)
author: Seb
author-url: /
date: 2024-12-01
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

### General/Unorganised Performance Related Things

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

- https://www.intel.com/content/www/us/en/developer/articles/technical/data-layout-optimization-using-simd-data-layout-templates.html

#### io_uring

System to perform asynchronous I/O with fewer system calls. Also supports
network operations. List of supported operations (as of 2024-12-01):

```
io_uring_prep_accept                   io_uring_prep_read
io_uring_prep_accept_direct            io_uring_prep_read_fixed
io_uring_prep_cancel                   io_uring_prep_readv
io_uring_prep_cancel64                 io_uring_prep_readv2
io_uring_prep_cancel_fd                io_uring_prep_recv
io_uring_prep_close                    io_uring_prep_recvmsg
io_uring_prep_close_direct             io_uring_prep_recvmsg_multishot
io_uring_prep_cmd                      io_uring_prep_recv_multishot
io_uring_prep_connect                  io_uring_prep_remove_buffers
io_uring_prep_fadvise                  io_uring_prep_rename
io_uring_prep_fallocate                io_uring_prep_renameat
io_uring_prep_fgetxattr                io_uring_prep_send
io_uring_prep_files_update             io_uring_prep_sendmsg
io_uring_prep_fsetxattr                io_uring_prep_sendmsg_zc
io_uring_prep_fsync                    io_uring_prep_send_set_addr
io_uring_prep_getxattr                 io_uring_prep_sendto
io_uring_prep_link                     io_uring_prep_send_zc
io_uring_prep_linkat                   io_uring_prep_send_zc_fixed
io_uring_prep_link_timeout             io_uring_prep_setxattr
io_uring_prep_madvise                  io_uring_prep_shutdown
io_uring_prep_mkdir                    io_uring_prep_socket
io_uring_prep_mkdirat                  io_uring_prep_socket_direct
io_uring_prep_msg_ring                 io_uring_prep_socket_direct_alloc
io_uring_prep_msg_ring_cqe_flags       io_uring_prep_splice
io_uring_prep_msg_ring_fd              io_uring_prep_statx
io_uring_prep_msg_ring_fd_alloc        io_uring_prep_symlink
io_uring_prep_multishot_accept         io_uring_prep_symlinkat
io_uring_prep_multishot_accept_direct  io_uring_prep_sync_file_range
io_uring_prep_nop                      io_uring_prep_tee
io_uring_prep_openat                   io_uring_prep_timeout
io_uring_prep_openat2                  io_uring_prep_timeout_remove
io_uring_prep_openat2_direct           io_uring_prep_timeout_update
io_uring_prep_openat_direct            io_uring_prep_unlink
io_uring_prep_poll_add                 io_uring_prep_unlinkat
io_uring_prep_poll_multishot           io_uring_prep_write
io_uring_prep_poll_remove              io_uring_prep_write_fixed
io_uring_prep_poll_update              io_uring_prep_writev
io_uring_prep_provide_buffers          io_uring_prep_writev2
```

- https://kernel.dk/io_uring.pdf
- https://unixism.net/loti/
- https://blog.cloudflare.com/missing-manuals-io_uring-worker-pool/
- https://developers.redhat.com/articles/2023/04/12/why-you-should-use-iouring-network-io

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
