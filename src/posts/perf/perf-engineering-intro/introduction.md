---
title: Foray into Performance Engineering
author: Seb
author-url: /
date: 2024-11-25
lang: en
toc-title: Contents
version: v1.0.0
---

## Introduction

This is an endeavour into learning more about various aspects of software
performance, and to become more acquainted with performance related
tools, technqiues and concepts, as well as becoming more familiar with some of the technologies
used in high performance computing. There were some tangents along the way which were
explored because they ended up being relevant, were interesting, or just for fun.

The main problem used to explore these goals is the mathematical integration of a function

$$  \int_{a}^{b} f(x) \,dx  $$

This was chosen for a variety of reasons:

- Low complexity to implement an approximate solution
- Answers can be compared to analytical solutions (where they exist) for correctness
- Straightforward to parallelise

The main language used to implement the functions used for testing is C.

This exploration is spread out over a few pages:

- The introduction and initial setup (this page)
- [A look at measurement tools/methods](measurement.md)
- [Optimisation techniques other than parallelisation](optimisations-singlecore.md)
- [Looking at different parallel programming methods](optimisations-multicore.md)

<hr>

## Initial Setup

### Code

To start, a couple mathematical functions were written along with their antiderivatives
(for result sanity checking).

$$ f'(x) = \cos {x} | f(x) = \sin {x} $$

$$ f'(x) = x e^x \cos {x} | f(x) = (1/2) e^x (x \cos {x} - \sin {x} + x \sin {x}) $$

In C:

```C
double f_simple(double x) {
    return cos(x);
}

double antiderivative_f_simple(double x) {
    return sin(x);
}

double f_intermediate(double x) {
    return (x * pow(M_E, x) * cos(x));
}

double antiderivative_f_intermediate(double x) {
    return (0.5 * pow(M_E, x) * (x*cos(x) - sin(x) + x*sin(x)));
}
```

Next, the integral functions were made. These were written to allow for arbitrary single parameter
functions to be provided. The analytical solution uses the [fundamental theorem of calculus](https://en.wikipedia.org/wiki/Fundamental_theorem_of_calculus) to
calculate the result of an integral, and assumes the function's antiderivative is provided.
The analytical solution will be used to sanity check the results of the Riemann integral
along this investigation.

```C
typedef double (*mathfunc_single_param_t)(double);

double integral_analytical(mathfunc_single_param_t antiderivative,
    double upper_bound, double lower_bound) {
    return (antiderivative(upper_bound) - antiderivative(lower_bound));
}
```

A simple [Riemann sum](https://en.wikipedia.org/wiki/Riemann_sum) integration solution is the main routine of interest for the future performance-related investigations. This calculates the integral
of a function by generating rectangles underneath the function and calculating their area, then
summing them together. As the number of rectangles becomes larger and larger, the result should
become more and more accurate (and approach the analytical solution for the functions chosen).

```C
double integral_riemann(mathfunc_single_param_t integrand,
    double upper_bound, double lower_bound, double split) {

    // Bounds checks are ignored
    double sum = 0.0;
    double step = (upper_bound - lower_bound) / split;

    // Calculate the (left) Riemann sum
    for (double n = lower_bound; n <= upper_bound; n += step) {
        sum += ((integrand(n)) * step);
    }

    return sum;
}
```

No optimisations are performed at this point (in fact anti-optimisations are included
by keeping the multiplication in the loop body), instead they are left for later.

<br>

### Sanity Checks

Before anything else, the Riemann sum functions are checked for correctness against the analytical
solution with a few tests. First, testing the simple function with the bounds 0 and `M_PI`, which should yield `0`:

```C
    double a = 0;
    double b = M_PI;
    double split = 1000;

    double ans_riemann = integral_riemann(f_simple, b, a, split);
    double ans_analytical = integral_analytical(antiderivative_f_simple, b, a);

    printf("Riemann:\t%g\n", ans_riemann);
    printf("Analytical:\t%g\n", ans_analytical);
```

Compiling with `gcc main.c -lm -Wall` and running yields:

```
Riemann:	    -6.245e-15
Analytical:	    1.22465e-16
```

Which is (close enough to) `0`, as expected. Decreasing the `split` variable in the above code
should reduce the accuracy of the approximation. With a `split` value of 10:

```
Riemann:    	    0.314159
Analytical:	    1.22465e-16
```

Changing the upper bound to `M_PI/2` (with a `split` back at `1000`):

```
Riemann:	    1.00079
Analytical:	    1
```

Next, the intermediate functions are tested. The testing code is almost the exact same as above,
expect with the `f_intermediate` and `antiderivative_f_intermediate` functions referenced instead.

With the bounds of `0 -> M_PI/4` and `split` of `1000`;

```
Riemann:	    0.443098
Analytical:	    0.442619
```

Changing the upper bound to `M_PI`:

```
Riemann:	    -36.4636
Analytical:	    -36.3493
```

Finally, the `split` value is changed to `1000000`, which should improve the accuracy:

```
Riemann:	    -36.3494
Analytical:	    -36.3493
```

With the sanity checks complete, we move on to performance measurement tools and techniques.

<br>
[Home](/)
<p style="text-align: right">
[Measurement Tooling](measurement.html)
</p>
