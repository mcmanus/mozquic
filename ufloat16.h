/*

The MIT License (MIT)

Copyright (c) 2017 Mikkel F. Jørgensen, dvide.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

/*

The IETF QUIC transport protocol draft November 2016 appears to provide
an incorrect example of a delta encoded timestamp in the ACK Frame
section because 0x800 maps to 2048, not 4096 as stated. While the format
description is otherwise largely correct, it is not very easy to follow
and it doesn't suggest an easy optimization when the encoded exponent is
1. Chromium implements this optimization as of January 2017.

The following definition seeks to describe the format more precisely so
that it is both easier to understand and to implement. It is supported
by a compact yet efficient reference implementation.


    QUIC uses a custom floating point format ufloat16 to represent a
    non-negative time delta in microseconds.

    The ufloat16 format encodes an unsigned 64-bit integer value k' as
    an unsigned 16-bit floating point value v with a non-negative
    exponent and with no special values like NaN (*). The decoded value
    k is given as k = m * 2^p where m and p are both derived from v and
    m is a 12-bit significand, including a hidden bit, and p is a 5-bit
    exponent in the range [0..30]. The encoding is lossy with k <= k'.

    The encoded 16-bit value v has two forms: either v = e(5)f(11), e >=
    2, or v = 0(4)m(12), e < 2. When e >= 2, the exponent p becomes p =
    e - 1 and the significand m becomes m = f + 2^11 which adds a most
    significant hidden bit. When e < 2 (and therefore v < 2^12),
    m and p become m = v and p = 0. The decoded value k thus becomes k =
    m * 2^p or, equivalently, k = v, v < 2^12, and otherwise k = (f +
    2^11) * 2^(e - 1). All values are unsigned.

    A simpler but less efficient interpretation of the same format is
    given by: v = e(5)f(11). When e > 0 then p = e - 1 and m = f + 2^11,
    otherwise m = f and p = e. k = m * 2^p. All values are unsigned.

    (*) When encoding an unsigned 64-bit value k', any value that would
    overflow the 16-bit encoded representation v is clamped to v =
    UFLOAT16_MAX = 2^16 - 1 = 0xFFFF. A decoded value k is no greater
    than UFLOAT16_UINT64_MAX = (2^12 - 1) * 2^30 = 0x3FFC0000000.

    For completeness: decoding a value v returns the lower bound k of
    any value k' that encodes to the same value v. The encoding is a
    total surjective monotonically increasing discrete function.

    On common hardware supporting unsigned 64-bit two's complement
    arithmetic, decoding from ufloat16 can be computed as `if v < (1 <<
    12) then return v; else p = (v >> 11) - 1; m = v - (p << 11); k = m
    << p; return k; endif`. Note that v - (p << 11) exposes the hidden
    bit while removing the exponent. Likewise, encoding to ufloat16 can
    be computed as `if k' < (1 << 12) then return k'; else if k' >=
    UFLOAT16_INT64_MAX then return UFLOAT16_MAX; else p =
    logbase2_floor(k' >> 11); v = (p << 11) + (k' >> p); return v;
    endif`. Note that adding (p << 11) intentionally overflows and hides
    the most significant bit and increments the exponent by one. The
    `logbase2_floor` operation only needs to handle non-zero unsigned
    32-bit integers because `0 < (k' >> 11) < 2^32` and often has
    hardware support (in C usually via __builtin_clz or
    _BitScanReverse), otherwise it can be implemented efficiently in
    software via 32-bit deBruijn multiplication.

*/

#ifndef UFLOAT16_H
#define UFLOAT16_H

#include <stdint.h>

#ifndef ufloat16_logbase2_floor

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#if defined(__GNUC__) || __has_builtin(__builtin_clz)

/* Undefined for `x == 0`. */
static inline int __ufloat16_logbase2_floor_builtin(uint32_t x)
{
    return 31 - __builtin_clz(x);
}

#define ufloat16_logbase2_floor(x) __ufloat16_logbase2_floor_builtin(x)

#elif defined(_MSC_VER)

#include <intrin.h>

/* Undefined for `x == 0`. */
static __inline int __ufloat16_logbase2_floor_msvc(uint32_t x)
{
    unsigned long Index = 0;
    _BitScanReverse(&Index, (unsigned long)x);
    return (int)Index;
}

#define ufloat16_logbase2_floor(x) __ufloat16_logbase2_floor_msvc(x)

#endif

#endif /* ufloat16_logbase2_floor */

#if !defined(__cplusplus) && defined(_MSC_VER) && !defined(inline)
#define __UFLOAT16_INLINE_PATCH
#define inline
#endif


/* -------------------------------------------------------- */
/*   This section can be extracted for reference purposes   */
/*   or as a minimal fully functioning implementation.      */
/* -------------------------------------------------------- */

#include <stdint.h>

#define UFLOAT16_MAX UINT16_C(0xFFFF)
#define UFLOAT16_UINT64_MAX UINT64_C(0x3FFC0000000)

/*
 * Optionally provide `ufloat16_logbase2_floor` hardware support.
 * It operates on unsigned 32-bit and may be undefined for 0.
 */

#ifndef ufloat16_logbase2_floor

static inline int __ufloat16_logbase2_floor_reference(uint32_t x)
{
    static const uint32_t K = UINT32_C(0x07C4ACDD);
    static const int deBruijn[32] =
    {
      0, 9, 1, 10, 13, 21, 2, 29, 11, 14, 16, 18, 22, 25, 3, 30,
      8, 12, 20, 28, 15, 17, 24, 7, 19, 27, 23, 6, 26, 5, 4, 31
    };

    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;

    return deBruijn[(uint32_t)(x * K) >> 27];
}

#define ufloat16_logbase2_floor(x) __ufloat16_logbase2_floor_reference(x)

#endif /* ufloat16_logbase2_floor */

static inline uint64_t ufloat16_decode(uint16_t v)
{
    uint16_t p;
    uint64_t m;

    if (v < (1 << 12)) {
        return v;
    }
    p = (v >> 11) - 1;
    m = v - (p << 11);
    return m << p;
}

static inline uint16_t ufloat16_encode(uint64_t k)
{
    uint16_t p;

    if (k < (1 << 12)) {
        return (uint16_t)k;
    }
    if (k >= UFLOAT16_UINT64_MAX) {
        return UFLOAT16_MAX;
    }
    p = (uint16_t)ufloat16_logbase2_floor((uint32_t)(k >> 11));
    return (uint16_t)(k >> p) + (p << 11);
}

/* ----------------------------------------------------- */


#ifdef  __UFLOAT16_INLINE_PATCH
#undef inline
#endif

#endif /* UFLOAT16_H */


#ifdef UFLOAT16_TEST

/*
 * To compile and run test:
 *
 *   cp ufloat16.h testufloat16.c
 *   cc -DUFLOAT16_TEST -Wall -Wpedantic testufloat16.c -o testufloat16
 *   ./testufloat16
 */

#include <stdio.h>


#define check_basic(x, s) ((x) || ((++ret) && printf("basic check at line %d failed: %s\n", __LINE__, s)))

static int verify_basic()
{
    int ret = 0;
    uint64_t k;
    uint16_t v;

    k = ufloat16_encode(0);
    v = ufloat16_decode(k);
    check_basic(k == 0, "k == 0");
    check_basic(v == 0, "v == 0");

    k = ufloat16_encode(1);
    v = ufloat16_decode(k);
    check_basic(k == 1, "k == 1");
    check_basic(v == 1, "v == 1");

    k = ufloat16_decode(2048);
    v = ufloat16_encode(k);
    check_basic(k == 2048, "k == 2048");
    check_basic(v == 0x0800, "v == 0x0800");

    k = ufloat16_decode(4096);
    v = ufloat16_encode(k);
    check_basic(k == 4096, "k == 4096");
    check_basic(v == 0x1000, "v == 0x1000");

    v = ufloat16_encode(UFLOAT16_UINT64_MAX);
    k = ufloat16_decode(v);
    check_basic(k == UFLOAT16_UINT64_MAX, "k == UFLOAT16_UINT64_MAX");
    check_basic(v == UFLOAT16_MAX, "v == UFLOAT16_MAX");

    v = ufloat16_encode(UFLOAT16_UINT64_MAX + 1);
    k = ufloat16_decode(v);
    check_basic(k == UFLOAT16_UINT64_MAX, "k == UFLOAT16_UINT64_MAX");
    check_basic(v == UFLOAT16_MAX, "v == UFLOAT16_MAX");

    v = ufloat16_encode(UINT64_MAX);
    k = ufloat16_decode(v);
    check_basic(k == UFLOAT16_UINT64_MAX, "k == UFLOAT16_UINT64_MAX");
    check_basic(v == UFLOAT16_MAX, "v == UFLOAT16_MAX");

    return ret > 0;
}


struct ufloat16_test_pair {
    uint64_t k;
    uint16_t v;
};

static const struct ufloat16_test_pair test_pairs[] =  {

    /* Small numbers represent themselves. */
    {0, 0},
    {1, 1},
    {2, 2},
    {3, 3},
    {4, 4},
    {5, 5},
    {6, 6},
    {7, 7},
    {15, 15},
    {31, 31},
    {42, 42},
    {123, 123},
    {1234, 1234},

    /* Check transition through 2^11. */
    {2046, 2046},
    {2047, 2047},
    {2048, 2048},
    {2049, 2049},

    /* Running out of significand at 2^12. */
    {4094, 4094},
    {4095, 4095},
    {4096, 4096},
    {4097, 4096},
    {4098, 4097},
    {4099, 4097},
    {4100, 4098},
    {4101, 4098},

    /* Check transition through 2^13. */
    {8190, 6143},
    {8191, 6143},
    {8192, 6144},
    {8193, 6144},
    {8194, 6144},
    {8195, 6144},
    {8196, 6145},
    {8197, 6145},

    /* Half-way through the exponents. */
    {0x7FF8000, 0x87FF},
    {0x7FFFFFF, 0x87FF},
    {0x8000000, 0x8800},
    {0xFFF0000, 0x8FFF},
    {0xFFFFFFF, 0x8FFF},
    {0x10000000, 0x9000},

    /* Transition into the largest exponent. */
    {0x1FFFFFFFFFE, 0xF7FF},
    {0x1FFFFFFFFFF, 0xF7FF},
    {0x20000000000, 0xF800},
    {0x20000000001, 0xF800},
    {0x2003FFFFFFE, 0xF800},
    {0x2003FFFFFFF, 0xF800},
    {0x20040000000, 0xF801},
    {0x20040000001, 0xF801},

    /* Transition into the max value and clamping. */
    {0x3FF80000000, 0xFFFE},
    {0x3FFBFFFFFFF, 0xFFFE},
    {0x3FFC0000000, 0xFFFF},
    {0x3FFC0000001, 0xFFFF},
    {0x3FFFFFFFFFF, 0xFFFF},
    {0x40000000000, 0xFFFF},
    {0xFFFFFFFFFFFFFFFF, 0xFFFF},

    /* Symbolic constants. */
    {UFLOAT16_UINT64_MAX, UFLOAT16_MAX},

};

static int verify_test_pair(int i, struct ufloat16_test_pair tp)
{
    uint64_t k, k2;
    uint16_t v;

    v = ufloat16_encode(tp.k);
    k = ufloat16_decode(tp.v);
    k2 = ufloat16_decode(tp.v + 1) - 1;

    if (v != tp.v || k > tp.k || k2 < tp.k) {
        printf("test pair %d failed: tp.k = 0x%08llX, tp.v = 0x%04X\n",
                i, (unsigned long long)tp.k, (unsigned)tp.v);
        printf("  got: k = 0x%08llX, k2 = 0x%08llX, v = 0x%04X\n",
                (unsigned long long)k, (unsigned long long)k2, (unsigned)v);
        return 1;
    }
    return 0;
}

static int verify_all_test_pairs()
{
    int ret = 0;
    size_t i, n;

    n = sizeof(test_pairs) / sizeof(test_pairs[0]);
    for (i = 0; i < n; ++i) {
        ret += verify_test_pair(i, test_pairs[i]);
        if (ret > 9) {
            printf("aborting all pairs test\n");
            return 1;
        }
    }
    return ret > 0;
}


#define check_order(i, x, s) ((x) || ((++ret) && printf("order iteration %d failed: %s\n", (int)i, s)))

static int verify_order()
{
    int ret = 0;
    int i;
    uint64_t a, b;
    uint16_t v;

    a = ufloat16_encode(0);
    v = ufloat16_decode(a);
    check_order(0, a == 0, "a == 0");
    check_order(0, v == 0, "v == 0");
    for (i = 1; i <= UFLOAT16_MAX; ++i) {
        b = ufloat16_decode(i);
        v = ufloat16_encode(b);
        check_order(i, a < b, "a < b");
        check_order(i, v == i, "v == i");
        if (ret > 9) {
            printf("aborting ordered test\n");
            return 1;
        }
        a = b;
    }
    return ret > 0;
}

int main(int argv, char **argc)
{
    if (verify_basic() || verify_all_test_pairs() || verify_order()) {
        return 1;
    }
    printf("Test passed!\n");
    return 0;
}

#endif /* UFLOAT16_TEST */
