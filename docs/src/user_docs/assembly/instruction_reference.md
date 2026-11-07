---
title: "Miden VM Instruction Reference"
sidebar_position: 12
---

# Miden VM Instruction Reference

This page describes the instructions accepted by Miden Assembly and their current lowering.

Stack diagrams put the top on the left. Uppercase letters denote four-element words; stack
depths and word indices are zero-based. Field elements use canonical representatives in
`[0, p)`, where $p = 2^{64} - 2^{32} + 1$. Field comparisons order those representatives as
integers.

Unless stated otherwise, **cycles** count raw VM operations emitted by the assembler, including
implicit system-event instructions. They exclude basic-block/control rows, operation-group and
batch padding, retained-call overhead, and procedure-local frame setup/cleanup. Consequently,
adding table entries does not necessarily give a program's executed cycle count or proof-trace
size. Control-flow costs are described separately below.

When a row combines a stack-operand instruction with `instruction.b`, its stack diagram shows
the stack-operand form. In the immediate form, `b` comes from the instruction and is absent from
the input stack. Immediate forms can have special lowerings; their cost is not necessarily the
cost of `push.b` followed by the stack-operand instruction.

## Field Operations

### Comparison Operations

| Instruction | Stack Input | Stack Output | Cycles | Notes |
| --- | --- | --- | --- | --- |
| `lte` / `lte.b` | `[b, a, ...]` | `[c, ...]` | 18 / 1 if b = 0, 19 otherwise | `c = 1` iff `a <= b`, otherwise 0. |
| `lt` / `lt.b` | `[b, a, ...]` | `[c, ...]` | 17 / 2 if b = 0, 18 otherwise | `c = 1` iff `a < b`, otherwise 0. |
| `gte` / `gte.b` | `[b, a, ...]` | `[c, ...]` | 17 / 3 if b = 0, 18 otherwise | `c = 1` iff `a >= b`, otherwise 0. |
| `gt` / `gt.b` | `[b, a, ...]` | `[c, ...]` | 16 / 2 if b = 0, 17 otherwise | `c = 1` iff `a > b`, otherwise 0. |
| `eq` / `eq.b` | `[b, a, ...]` | `[c, ...]` | 1 / 1 if b = 0, 2 otherwise | `c = 1` iff `a = b`, otherwise 0. |
| `neq` / `neq.b` | `[b, a, ...]` | `[c, ...]` | 2 / 2 if b = 0, 3 otherwise | `c = 1` iff `a != b`, otherwise 0. |
| `eqw` | `[A, B, ...]` | `[c, A, B, ...]` | 15 | `c = 1` iff all corresponding elements of `A` and `B` are equal. Preserves both words. |
| `is_odd` | `[a, ...]` | `[b, ...]` | 6 | `b = 1` iff the canonical representative of `a` is odd, otherwise 0. |

### Assertions and Tests

| Instruction | Stack Input | Stack Output | Cycles | Notes |
| --- | --- | --- | ---: | --- |
| `assert` | `[a, ...]` | `[...]` | 1 | Consumes `a`; fails unless `a = 1`. |
| `assertz` | `[a, ...]` | `[...]` | 2 | Consumes `a`; fails unless `a = 0`. |
| `assert_eq` | `[b, a, ...]` | `[...]` | 2 | Consumes `a, b`; fails unless they are equal. |
| `assert_eqw` | `[B, A, ...]` | `[...]` | 11 | Consumes both words; fails unless all corresponding elements are equal. |

Assertions accept an error message, for example `assert.err="Division by 0"`, or an error
constant. `.err` changes the diagnostic code without adding operations.

### Arithmetic and Boolean Operations

| Instruction | Stack Input | Stack Output | Cycles | Notes |
| --- | --- | --- | --- | --- |
| `add` / `add.b` | `[b, a, ...]` | `[c, ...]` | 1 / 1 if b = 0 or 1, 2 otherwise | $c = (a+b) \bmod p$. |
| `sub` / `sub.b` | `[b, a, ...]` | `[c, ...]` | 2 / 1 if b = 0, 2 otherwise | $c = (a-b) \bmod p$. |
| `mul` / `mul.b` | `[b, a, ...]` | `[c, ...]` | 1 / 1 if b = 1, 2 otherwise | $c = ab \bmod p$. |
| `div` / `div.b` | `[b, a, ...]` | `[c, ...]` | 2 / 1 if b = 1, 2 otherwise | $c = ab^{-1} \bmod p$. Dynamic zero division fails at execution; `div.0` is rejected by the assembler. Field division is not floor division; use `u32div` for floor division. |
| `neg` | `[a, ...]` | `[b, ...]` | 1 | $b = -a \bmod p$. |
| `inv` | `[a, ...]` | `[b, ...]` | 1 | $b = a^{-1} \bmod p$. Fails if `a = 0`. |
| `pow2` | `[a, ...]` | `[b, ...]` | 16 | `b = 2^a`. Requires `0 <= a <= 63`. |
| `exp` / `exp.uN` | `[b, a, ...]` | `[c, ...]` | 72 / 9 + N | $c = a^b$. `exp` is `exp.u63`. `N` is in `0..=63`; execution fails unless `b < 2^N`. `exp.u0` accepts only exponent 0 and returns 1. |
| `exp.b` | `[a, ...]` | `[c, ...]` | See notes | $c = a^b$ for a canonical field-element immediate `b`. |
| `ilog2` | `[a, ...]` | `[b, ...]` | 70 | `b = floor(log2(a))`. Fails if `a = 0`. Includes the advice system event and verification of its result. |
| `not` | `[a, ...]` | `[b, ...]` | 1 | `b = 1-a`. Requires `a` in `{0,1}`; execution rejects other values. |
| `and` | `[b, a, ...]` | `[c, ...]` | 1 | `c = a*b`. Requires both operands in `{0,1}`; execution rejects other values. |
| `or` | `[b, a, ...]` | `[c, ...]` | 1 | `c = a+b-a*b`. Requires both operands in `{0,1}`; execution rejects other values. |
| `xor` | `[b, a, ...]` | `[c, ...]` | 7 | `c = a+b-2*a*b`. Requires both operands in `{0,1}`; execution rejects other values. |
| `nop` | `[...]` | `[...]` | 1 | No operand-stack or memory effect; advances the VM clock. |

`add.0`, `sub.0`, `mul.1`, and `div.1` each emit one no-op, rather than zero instructions.
`mul.0` emits two operations. For `exp.b`, the costs for `b = 0,1,...,8` are respectively
`3,1,2,4,4,6,6,8,6`; `b = 16` costs 8. Every other immediate exponent costs
$11 + \lfloor \log_2(b) \rfloor$. Unlike dynamic `exp`, the immediate form also supports
canonical exponents whose highest set bit is bit 63.

### Extension Field Operations

These operations use $\mathbb{F}_p[x]/(x^2-7)$. An extension element `(a0,a1)` represents
$a_0+a_1x$, with the low coefficient on top of the stack.

| Instruction | Stack Input | Stack Output | Cycles | Notes |
| --- | --- | --- | ---: | --- |
| `ext2add` | `[b0,b1,a0,a1,...]` | `[c0,c1,...]` | 5 | `c0 = a0+b0`, `c1 = a1+b1`, modulo p. |
| `ext2sub` | `[b0,b1,a0,a1,...]` | `[c0,c1,...]` | 7 | `c0 = a0-b0`, `c1 = a1-b1`, modulo p. |
| `ext2mul` | `[b0,b1,a0,a1,...]` | `[c0,c1,...]` | 3 | `c0 = a0*b0+7*a1*b1`, `c1 = a0*b1+a1*b0`, modulo p. |
| `ext2neg` | `[a0,a1,...]` | `[a0',a1',...]` | 4 | Negates both coefficients modulo p. |
| `ext2inv` | `[a0,a1,...]` | `[a0',a1',...]` | 11 | Returns the multiplicative inverse; fails if both input coefficients are zero. Includes the advice system event and verification. |
| `ext2div` | `[b0,b1,a0,a1,...]` | `[c0,c1,...]` | 14 | Returns `a * b^-1`; fails if both coefficients of b are zero. Includes the advice system event and verification. |

## U32 Operations

These instructions operate on unsigned 32-bit values unless a row explicitly accepts a full field element. Arithmetic and comparison operands must be less than `2^32`; the current processor rejects out-of-range operands of their underlying U32 operations. The shift/rotate input-domain exceptions are noted below.

For paired register/immediate spellings, the stack-input column describes the register form. The immediate form supplies `b` in the instruction and omits it from the input stack. Define `P(b) = 2` when `b = 1`, and `P(b) = 1` otherwise: an immediate push of zero emits Pad, one emits Pad/Incr, and other values emit one Push. Every u32 immediate is in `0..=2^32-1`, except shift/rotate immediates, which are in `0..=31`.

### Conversions and Tests

| Instruction | Stack Input | Stack Output | Cycles | Notes |
| --- | --- | --- | --- | --- |
| `u32test` | `[a, ...]` | `[a < 2^32, a, ...]` | 4 | Accepts any canonical field element and preserves it. |
| `u32testw` | `[A, ...]` | `[all_u32, A, ...]` | 19 | True iff every coordinate of A is less than `2^32`. |
| `u32assert` | `[a, ...]` | `[a, ...]` | 3 | Fails unless a is u32. |
| `u32assert2` | `[b, a, ...]` | `[b, a, ...]` | 1 | Fails unless both are u32. |
| `u32assertw` | `[A, ...]` | `[A, ...]` | 6 | Fails unless all four coordinates are u32. |
| `u32cast` | `[a, ...]` | `[lo, ...]` | 3 | Accepts any canonical Felt; `lo = a mod 2^32`. |
| `u32split` | `[a, ...]` | `[lo, hi, ...]` | 1 | Accepts any canonical Felt; `lo = a mod 2^32`, `hi = floor(a/2^32)`. |

U32 assertions accept `.err="message"` or a named error constant without changing the raw cycle count.

### Arithmetic Operations

Here `lo(x) = x mod 2^32`, `hi(x) = floor(x/2^32)`. Carry/borrow ordering is intentional: widening results put the low limb first; overflowing forms put carry/borrow first.

| Instruction | Stack Input | Stack Output | Cycles (stack / immediate) | Notes |
| --- | --- | --- | --- | --- |
| `u32widening_add` / `u32widening_add.b` | `[b, a, ...]` | `[lo(a+b), hi(a+b), ...]` | `1 / 1+P(b)` | Two-limb sum, low limb on top. |
| `u32overflowing_add` / `u32overflowing_add.b` | `[b, a, ...]` | `[hi(a+b), lo(a+b), ...]` | `2 / 2+P(b)` | Carry on top. |
| `u32wrapping_add` / `u32wrapping_add.b` | `[b, a, ...]` | `[lo(a+b), ...]` | `3 / 3+P(b)` | Discards carry. |
| `u32widening_add3` | `[c, b, a, ...]` | `[lo(a+b+c), hi(a+b+c), ...]` | 1 | The high limb can be 0, 1, or 2. |
| `u32overflowing_add3` | `[c, b, a, ...]` | `[hi(a+b+c), lo(a+b+c), ...]` | 2 | The high limb is not necessarily a bit. |
| `u32wrapping_add3` | `[c, b, a, ...]` | `[lo(a+b+c), ...]` | 3 | Discards high limb. |
| `u32overflowing_sub` / `u32overflowing_sub.b` | `[b, a, ...]` | `[borrow, lo(a-b), ...]` | `1 / 1+P(b)` | `borrow = 1` iff `a < b`. |
| `u32wrapping_sub` / `u32wrapping_sub.b` | `[b, a, ...]` | `[lo(a-b), ...]` | `2 / 2+P(b)` | Discards borrow. |
| `u32widening_mul` / `u32widening_mul.b` | `[b, a, ...]` | `[lo(a*b), hi(a*b), ...]` | `1 / 1+P(b)` | Low product limb on top. |
| `u32wrapping_mul` / `u32wrapping_mul.b` | `[b, a, ...]` | `[lo(a*b), ...]` | `3 / 3+P(b)` | Lowers to U32mul, Swap, Drop. |
| `u32widening_madd` | `[b, a, c, ...]` | `[lo(a*b+c), hi(a*b+c), ...]` | 1 | Low result limb on top. |
| `u32wrapping_madd` | `[b, a, c, ...]` | `[lo(a*b+c), ...]` | 3 | Discards high limb. |
| `u32div` / `u32div.b` | `[b, a, ...]` | `[floor(a/b), ...]` | `2 / 2+P(b)` | Runtime divisor zero fails; immediate divisor zero is an assembly error. |
| `u32mod` / `u32mod.b` | `[b, a, ...]` | `[a mod b, ...]` | `3 / 3+P(b)` | Same divisor-zero rules. |
| `u32divmod` / `u32divmod.b` | `[b, a, ...]` | `[a mod b, floor(a/b), ...]` | `1 / 1+P(b)` | Remainder on top, quotient beneath. Same divisor-zero rules. |

Thus, for example, `u32wrapping_mul.0` or `.2` costs 4 raw operations, `.1` costs 5, and neither zero nor one is optimized to a field operation/Noop. The U32 input check remains.

When both quotient and remainder are needed, `u32divmod.2` produces both in two raw operations,
with the remainder on top and quotient beneath it.

### Bitwise Operations

| Instruction | Stack Input | Stack Output | Cycles (stack / immediate) | Notes |
| --- | --- | --- | --- | --- |
| `u32and` / `u32and.b` | `[b, a, ...]` | `[a AND b, ...]` | `1 / 1+P(b)` | Fails for non-u32 operands. |
| `u32or` / `u32or.b` | `[b, a, ...]` | `[a OR b, ...]` | `6 / 6+P(b)` | Fails for non-u32 operands. |
| `u32xor` / `u32xor.b` | `[b, a, ...]` | `[a XOR b, ...]` | `1 / 1+P(b)` | Fails for non-u32 operands. |
| `u32not` | `[a, ...]` | `[2^32-1-a, ...]` | 5 | Fails for non-u32 a. |
| `u32not.b` | `[...]` | `[2^32-1-b, ...]` | `5+P(b)` | Expands to `push.b u32not`; **preserves the existing stack**, unlike unary register form. |
| `u32shl` / `u32shl.b` | `[b, a, ...]` | `[(a*2^b) mod 2^32, ...]` | `19 / 1 if b=0, 4 otherwise` | Requires u32 a and b in 0..31. |
| `u32shr` / `u32shr.b` | `[b, a, ...]` | `[floor(a/2^b), ...]` | `18 / 1 if b=0, 3 otherwise` | Requires u32 a and b in 0..31. |
| `u32rotl` / `u32rotl.b` | `[b, a, ...]` | `[rotl32(a,b), ...]` | `18 / 1 if b=0, 3 otherwise` | Requires u32 a and b in 0..31. |
| `u32rotr` / `u32rotr.b` | `[b, a, ...]` | `[rotr32(a,b), ...]` | `23 / 1 if b=0, 3 otherwise` | Requires u32 a and b in 0..31; dynamic form does not validate a as u32. |
| `u32popcnt` | `[a, ...]` | `[popcount32(a), ...]` | 36 | Result is in 0..32. Current processor rejects non-u32 a. |
| `u32clz` | `[a, ...]` | `[leading_zeros32(a), ...]` | 52 | Includes 3-op system event plus AdvPop and 48-op verification. Zero returns 32. |
| `u32ctz` | `[a, ...]` | `[trailing_zeros32(a), ...]` | 38 | 3-op event + AdvPop + 34-op verification. Zero returns 32. |
| `u32clo` | `[a, ...]` | `[leading_ones32(a), ...]` | 43 | 3-op event + AdvPop + 39-op verification. `2^32-1` returns 32. |
| `u32cto` | `[a, ...]` | `[trailing_ones32(a), ...]` | 37 | 3-op event + AdvPop + 33-op verification. `2^32-1` returns 32. |

All immediate-zero shifts/rotations are one Noop: they leave their value unchanged and do not check its u32 range. For nonzero immediate shifts/rotations, the assembler pushes the power-of-two multiplier/divisor directly, so `P(b)` does not apply. Literal shift/rotate immediates outside 0..31 are rejected by the parser (constant forms are checked during assembly). The bit-count system events require u32 a and supply hints that MASM independently verifies.

For u32 inputs, `u32and.3` and `u32and.7` compute the same remainders as `u32mod.4` and
`u32mod.8`, respectively, in two raw operations instead of four. `u32and.1` computes parity
in three operations; `is_odd` costs six but also accepts field elements outside the u32 range.

### Comparison Operations

| Instruction | Stack Input | Stack Output | Cycles (stack / immediate) | Notes |
| --- | --- | --- | --- | --- |
| `u32lt` / `u32lt.b` | `[b, a, ...]` | `[a < b, ...]` | `3 / 3+P(b)` | Current processor rejects non-u32 operands. |
| `u32lte` / `u32lte.b` | `[b, a, ...]` | `[a <= b, ...]` | `5 / 5+P(b)` | Same input requirement. |
| `u32gt` / `u32gt.b` | `[b, a, ...]` | `[a > b, ...]` | `4 / 4+P(b)` | Same input requirement. |
| `u32gte` / `u32gte.b` | `[b, a, ...]` | `[a >= b, ...]` | `4 / 4+P(b)` | Same input requirement. |
| `u32min` / `u32min.b` | `[b, a, ...]` | `[min(a,b), ...]` | `8 / 8+P(b)` | Same input requirement. |
| `u32max` / `u32max.b` | `[b, a, ...]` | `[max(a,b), ...]` | `7 / 7+P(b)` | Same input requirement. |

## Stack Manipulation

Only the top 16 elements are directly addressable. Every depth and word index below is
zero-based: `swap.1` exchanges depths 0 and 1; `movup.2` moves the third element to the top.

| Instruction | Stack Input | Stack Output | Cycles | Notes |
| --- | --- | --- | --- | --- |
| `drop` | `[a,...]` | `[...]` | 1 | Consumes the top element. |
| `dropw` | `[A,...]` | `[...]` | 4 | Consumes the top word. |
| `padw` | `[...]` | `[0,0,0,0,...]` | 4 | Pushes a zero word. |
| `dup.n` | `[...,a,...]` | `[a,...,a,...]` | 3 if n is 8, 10, 12, or 14; 1 otherwise | Copies depth n; `n` is in `0..=15`. `dup` means `dup.0`. |
| `dupw.n` | `[...,A,...]` | `[A,...,A,...]` | 4 | Copies word n; `n` is in `0..=3`. `dupw` means `dupw.0`. |
| `swap.n` | `[a,...,b,...]` | `[b,...,a,...]` | 1 for n = 1; 2 for n = 2..8; 5 for n = 9; 6 for n = 10..15 | Exchanges the top element with depth n. `swap` means `swap.1`. |
| `swapw.n` | `[A,...,B,...]` | `[B,...,A,...]` | 1 | Exchanges the top word with word n; `n` is in `1..=3`. `swapw` means `swapw.1`. |
| `swapdw` | `[D,C,B,A,...]` | `[B,A,D,C,...]` | 1 | Swaps the top two double words; each letter denotes one word. |
| `movup.n` | `[...,a,...]` | `[a,...]` | 1 for n = 2..8; 4 for n = 9..15 | Removes the element at depth n and inserts it at the top. |
| `movdn.n` | `[a,...]` | `[...,a,...]` | 1 for n = 2..8; 4 for n = 9..15 | Removes the top element and inserts it at depth n. |
| `movupw.n` | `[...,A,...]` | `[A,...]` | 2 for n = 2; 3 for n = 3 | Removes word n and inserts it at the top. |
| `movdnw.n` | `[A,...]` | `[...,A,...]` | 2 for n = 2; 3 for n = 3 | Removes the top word and inserts it at word index n. |
| `reversew` | `[a,b,c,d,...]` | `[d,c,b,a,...]` | 3 | Reverses the top word's four elements. |
| `reversedw` | `[a0,a1,a2,a3,a4,a5,a6,a7,...]` | `[a7,a6,a5,a4,a3,a2,a1,a0,...]` | 7 | Reverses the top double word's eight elements. |

### Conditional Manipulation

Every condition must be 0 or 1; execution rejects other values.

| Instruction | Stack Input | Stack Output | Cycles | Notes |
| --- | --- | --- | ---: | --- |
| `cswap` | `[c,b,a,...]` | `[a,b,...]` if c = 1; `[b,a,...]` otherwise | 1 | Consumes the condition, preserving both data elements. |
| `cswapw` | `[c,B,A,...]` | `[A,B,...]` if c = 1; `[B,A,...]` otherwise | 1 | Consumes the condition, preserving both data words. |
| `cdrop` | `[c,b,a,...]` | `[b,...]` if c = 1; `[a,...]` otherwise | 2 | Consumes the condition and the unselected element. |
| `cdropw` | `[c,B,A,...]` | `[B,...]` if c = 1; `[A,...]` otherwise | 5 | Consumes the condition and the unselected word. |

## Input/Output Operations

Instructions for moving data between the stack and other sources like program code, environment, advice provider, and memory.

### Constant Inputs

For scalar pushes define `P(a) = 2` if `a = 1`, and `P(a) = 1` otherwise: zero emits Pad,
one emits Pad/Incr, and every other scalar emits one Push.

| Instruction | Stack Input | Stack Output | Cycles | Notes |
| --- | --- | --- | --- | --- |
| `push.a.b.c` | `[...]` | `[c,b,a,...]` | Sum of P for all literals | Pushes 1–16 canonical field-element literals in source order; the last scalar ends on top. |
| `push.[a,b,c,d]` | `[...]` | `[a,b,c,d,...]` | `P(a)+P(b)+P(c)+P(d)` | Pushes one word, with element 0 on top. `push.[1,2,3,4]` costs 5 operations. Named word constants use the same ordering. |
| `push.WORD[start..end]` | `[...]` | Selected elements, first selected element on top | Sum of P for selected elements | Pushes a nonempty slice of a word constant; `0 <= start < end <= 4`. |

Decimal and hexadecimal literals are accepted. Short hexadecimal scalars use the usual
most-significant-digit-first notation; an exact 32-byte hexadecimal word uses little-endian
word encoding. A scalar list and a word therefore have different push-order conventions.

### Environment Inputs

| Instruction | Stack Input | Stack Output | Cycles | Notes |
| --- | --- | --- | ---: | --- |
| `clk` | `[...]` | `[t,...]` | 1 | Pushes the current VM clock cycle. |
| `sdepth` | `[...]` | `[d,...]` | 1 | Pushes the current operand-stack depth, which is at least 16. |
| `caller` | `[W,...]` | `[KEY,...]` | 1 | Overwrites the top word with the current context's principal procedure key. Entry establishes the execution descriptor's entry key; `call`/`dyncall` establish their requested key; `exec`, `dynexec`, and `syscall` preserve it; returns restore it. This is a callable key, not an implementation commitment. |
| `locaddr.i` | `[...]` | `[address,...]` | 4 | Pushes the absolute address of allocated local i. The procedure must allocate locals and i must be in range; invalid local references are assembly errors. |
| `procref.name` | `[...]` | `[KEY,...]` | 4 | Pushes the namespace-qualified callable key of `name`, with key[0] on top. It does not freeze an implementation or authenticate a binding. |

### Nondeterministic Inputs (Advice Provider)

#### Reading from Advice Stack

| Instruction  | Stack Input      | Stack Output     | Cycles | Notes                                                                                                                                                                           |
| ------------ | ---------------- | ---------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `adv_push` | `[ ... ]`        | `[a, ...]`       | 1      | Pops 1 value from advice stack and pushes onto operand stack. Fails if advice stack is empty.                                      |
| `adv_pushw` | `[ ... ]`        | `[A, ...]`       | 5      | Equivalent to `padw adv_loadw`. Pushes a word from advice onto the stack (grows by 4). Fails if advice stack has `< 4` values.                                      |
| `adv_loadw`  | `[W, ...]` | `[A, ...]`       | 1      | Pops word `A` (4 elements) from advice stack, overwrites top word of operand stack. Fails if advice stack has `< 4` values.                                                     |
| `adv_pipe`   | `[A,B,C,a,...]`  | `[A',B',C,a+8,...]` | 1      | Pops 2 words from advice stack, overwrites top 2 words (positions 0-7). C (positions 8-11) unchanged. Writes both words to memory at `a` and `a+4`. `a' = a+8`. Fails if advice stack has `< 8` values. |

#### Advice Provider and Deferred-State System Events (3 cycles)

Each event lowers to Push(event_id), Emit, Drop and preserves the operand stack. Host work
and returned advice are not authenticated merely by emitting the event; proof-relevant values
must be checked by VM instructions. Host resource limits can reject an event. Missing-key
lookups fail, except `adv.has_mapkey`, which explicitly reports whether a key is present.


_Push to Advice Stack:_

| Instruction             | Stack Input       | Stack Output      | Notes                                                                                           |
| ----------------------- | ----------------- | ----------------- | ----------------------------------------------------------------------------------------------- |
| `adv.push_mapval`       | `[K, ... ]`       | `[K, ... ]`       | Pushes values from `advice_map[K]` to advice stack.                                             |
| `adv.push_mapval_count` | `[K, ... ]`       | `[K, ... ]`       | Pushes number of elements in `advice_map[K]` to advice stack.                                   |
| `adv.push_mapvaln` / `adv.push_mapvaln.0` | `[K,...]` | `[K,...]` | Pushes advice `[n, values...]`, where n is the unpadded element count. |
| `adv.push_mapvaln.4` / `adv.push_mapvaln.8` | `[K,...]` | `[K,...]` | Pushes advice `[n, values..., zero_padding...]`, rounding the payload length up to a multiple of 4 or 8. The count n remains unpadded. Only suffixes 0, 4, and 8 are accepted. |
| `adv.has_mapkey` | `[K,...]` | `[K,...]` | Pushes an advice bit indicating whether K is in the advice map. This host lookup does not prove committed membership or absence. |
| `adv.push_mtnode`       | `[d, i, R, ... ]` | `[d, i, R, ... ]` | Pushes Merkle tree node (root `R`, depth `d`, index `i`) from Merkle store to advice stack.     |
| `adv.evaluate_deferred` | `[NODE_DIGEST, ...]` | `[NODE_DIGEST, ...]` | Evaluates a registered deferred node and pushes its canonical frame and payload felts to the advice stack. See deferred DAG details below. |
| `adv.evaluate_deferred_frame` | `[NODE_DIGEST, ...]` | `[NODE_DIGEST, ...]` | Evaluates a registered deferred node and pushes only its canonical frame to the advice stack. |
| `adv.evaluate_deferred_payload` | `[NODE_DIGEST, ...]` | `[NODE_DIGEST, ...]` | Evaluates a registered deferred node and pushes only its canonical payload felts to the advice stack. |

_Deferred DAG (host-side registration; no advice output):_

| Instruction             | Stack Input       | Stack Output      | Notes                                                                                           |
| ----------------------- | ----------------- | ----------------- | ----------------------------------------------------------------------------------------------- |
| `adv.register_deferred` | `[CV, PAYLOAD_LO, PAYLOAD_HI, ...]` | `[CV, PAYLOAD_LO, PAYLOAD_HI, ...]` | Registers and eagerly evaluates an operand-stack deferred node. Produces no advice output. See deferred DAG details below. |
| `adv.register_deferred_data` | `[n_chunks, CV, ptr, ...]` | `[n_chunks, CV, ptr, ...]` | Registers and eagerly evaluates a memory-backed deferred node. Produces no advice output. See deferred DAG details below. |

Deferred DAG details:

- The initial `CV`, the frame returned by evaluation, and every digest each occupy one word (4
  field elements). `CV` is derived from `(domain_tag, param0, param1, param2)`. The selected domain
  defines the three parameters. One deferred data chunk is 8 field elements, i.e. two words.
- `adv.register_deferred` accepts exactly one stack-resident payload block:
  `PAYLOAD_LO || PAYLOAD_HI` (8 field elements).
  - Data frames interpret those eight felts as a one-chunk data payload.
  - Precompile-owned join frames interpret them as `lhs_digest || rhs_digest`.
  - Pair-list frames interpret them as one `lhs_digest || rhs_digest` pair.

  The exact framework AND frame registers `AND(lhs_digest, rhs_digest)` without changing the
  built-in deferred root. Parameterized AND-domain frames and `TRUE` nodes are rejected. Frames that
  semantically require more data chunks or pairs fail during precompile evaluation. Code that later
  uses the node digest must compute it inside the VM from the same `CV`, `PAYLOAD_LO`, and
  `PAYLOAD_HI` values.
- `adv.register_deferred_data` accepts data, pair-list, and precompile-owned join frames. Its
  stack-supplied `n_chunks`, `CV`, and `ptr` are visible in the VM execution trace, but the event
  does not AIR-bind the host-read contents to memory.
  - Data frames read exactly `n_chunks` 8-felt chunks from word-aligned `ptr`.
  - Pair-list frames interpret those chunks as `lhs_digest || rhs_digest` pairs.
  - Precompile-owned join frames require `n_chunks == 1` and interpret the chunk as
    `lhs_digest || rhs_digest`.

  Framework-owned AND and `TRUE` nodes are not accepted. Rolling AND nodes are constructed by
  `log_deferred`. Code that later relies on the node must compute its digest with VM instructions
  from the same `CV` and ordered chunk sequence. The `register_mem` wrapper does this by hashing the
  exact range `[ptr, ptr + 8 * n_chunks)` with one absorption per chunk.
- `adv.evaluate_deferred` requires `NODE_DIGEST` to be already registered. It pushes the canonical
  frame followed by the canonical payload in advice-pop order. For a single 8-felt payload,
  `adv_pushw adv_pushw adv_pushw` leaves `[PAYLOAD_LO, PAYLOAD_HI, FRAME, ...]` on the operand
  stack.
  `TRUE` emits one zero word in the frame slot.
- `adv.evaluate_deferred_frame` pushes only the canonical frame. `TRUE` emits one zero word in the
  frame slot.
- `adv.evaluate_deferred_payload` pushes only the canonical payload to the advice stack.
  - Data payloads are arranged per 8-felt chunk as `HIGH` then `LOW` in advice-pop order, so
    `adv_pushw adv_pushw` leaves `LOW` above `HIGH` on the operand stack. Chunks preserve canonical
    chunk order.
  - Join payloads use the same two-word LIFO convention, leaving `lhs_digest` above `rhs_digest`
    after two `adv_pushw`s.
  - `TRUE` emits no advice.
- `adv.export_deferred_witness` stores a registered true assertion's witness under its original
  digest, replacing any existing advice value. The selected node may be unlogged, but cannot be
  literal `TRUE_DIGEST`. Both stacks and the deferred root are preserved; failed exports leave
  existing advice unchanged. See [nondeterministic inputs](io_operations.md#nondeterministic-inputs)
  for the encoded value and witness-validation requirements. The system event is
  `sys::adv::export_deferred_witness`.
- All `adv.evaluate_deferred*` outputs, including frame-only output, are host-provided hints. Before
  proof-relevant use, code must relate them with VM instructions to values established independently
  of that advice.

_Insert into Advice Map:_

| Instruction           | Stack Input          | Stack Output         | Notes                                                                                  |
| --------------------- | -------------------- | -------------------- | -------------------------------------------------------------------------------------- |
| `adv.export_deferred_witness` | `[NODE_DIGEST, ...]` | `[NODE_DIGEST, ...]` | Stores the witness under its digest, replacing any existing value. Preserves both stacks and the deferred root. |
| `adv.insert_mem`      | `[K, a, b, ... ]`    | `[K, a, b, ... ]`    | `advice_map[K] ← mem[a..b)`, with `0 <= a <= b < 2^32`; unwritten elements read as zero. No alignment is required. This host read does not itself authenticate the payload against VM memory.                                                           |
| `adv.insert_hdword`   | `[A, B, ... ]`       | `[A, B, ... ]`       | `K ← hdword(A \|\| B)` (top first). `advice_map[K] ← [A,B]`. |
| `adv.insert_hqword`   | `[A, B, C, D, ... ]` | `[A, B, C, D, ... ]` | `K ← hash_elements([A,B,C,D])`. `advice_map[K] ← [A,B,C,D]`. |
| `adv.insert_compress` | `[BLOCK_LO, BLOCK_HI, CV, ...]` | `[BLOCK_LO, BLOCK_HI, CV, ...]` | `K ← Eidos::compress(CV, BLOCK_LO \|\| BLOCK_HI)`. `advice_map[K] ← [BLOCK_LO, BLOCK_HI]`. |

Normal advice-map insertions accept an identical existing payload idempotently and reject a
conflicting value. `adv.export_deferred_witness` is the explicit replacement operation.

`adv_pipe` requires a word-aligned u32 address and space for both output words. Its incoming
block words may contain arbitrary values, and its third word is preserved.

### Random Access Memory

Each execution context has its own zero-initialized Felt-addressed memory in `[0, 2^32)`.
Word accesses require a multiple-of-four starting address. Globals conventionally use the
first $2^{31}$ addresses; local frames begin at $2^{31}$. Local frames share the context's
ordinary memory, are reused, and are not cleared between activations. Programs must avoid
aliasing general-purpose storage with live local frames or reserved execution metadata.

#### Absolute Addressing

For immediate-address forms, omit `a` from the stack input. An immediate scalar load pushes
its value; a stack-address scalar load replaces the address. A word load overwrites the four
slots below a dynamic address, or the existing top word for an immediate address. These
slots may contain arbitrary values and need not be zero.

| Instruction | Stack Input | Stack Output | Cycles (stack / immediate) | Notes |
| --- | --- | --- | --- | --- |
| `mem_load` / `mem_load.a` | `[a,...]` | `[v,...]` | 1 / 2, or 3 if a = 1 | Reads `mem[a]`. |
| `mem_loadw_le` / `mem_loadw_le.a` | `[a,W,...]` | `[A,...]` | 1 / 2 | Reads `mem[a..a+4)` in memory order, with `mem[a]` on top. |
| `mem_loadw_be` / `mem_loadw_be.a` | `[a,W,...]` | `[A,...]` | 4 / 5 | Reads the word in reverse element order, with `mem[a+3]` on top. Equivalent to `mem_loadw_le reversew`. |
| `mem_store` / `mem_store.a` | `[a,v,...]` | `[...]` | 2 / 3, or 4 if a = 1 | Writes v to `mem[a]` and consumes v. |
| `mem_storew_le` / `mem_storew_le.a` | `[a,A,...]` | `[A,...]` | 1 / 2 | Writes the top word in memory order; retains A. |
| `mem_storew_be` / `mem_storew_be.a` | `[a,A,...]` | `[A,...]` | 9 / 8 | Writes A in reverse element order; retains A in its original stack order. |
| `mem_stream` | `[A,B,C,a,...]` | `[D,E,C,a+8,...]` | 1 | Reads D from `mem[a..a+4)` and E from `mem[a+4..a+8)`, replacing A and B while preserving C. |

Addresses and accessed ranges must fit in u32 memory. An immediate address of 1 adds one
operation to all immediate memory lowerings, including word lowerings, but is invalid for a
word access because it is unaligned. The word-immediate costs above describe aligned accesses.
Both words accessed by `mem_stream` must fit in memory.

#### Procedure Locals (Context-Specific)

`@locals(N)` declares at most 65,532 locals, with allocation rounded up to a multiple of four.
Scalar indices must satisfy `i < N`; word indices must be multiples of four with `i+4 <= N`.
Invalid indices are assembly errors. Each nonzero local frame adds seven raw allocation and
seven deallocation operations, separate from the access costs below. Inlining a selected
procedure body retains its frame setup and cleanup. Reused local values are not initialized
to zero.

| Instruction | Stack Input | Stack Output | Cycles | Notes |
| --- | --- | --- | ---: | --- |
| `loc_load.i` | `[...]` | `[v,...]` | 5 | Pushes `local[i]`. |
| `loc_loadw_le.i` | `[W,...]` | `[A,...]` | 5 | Overwrites W with `local[i..i+4)` in memory order. |
| `loc_loadw_be.i` | `[W,...]` | `[A,...]` | 8 | Overwrites W with the word in reverse element order. |
| `loc_store.i` | `[v,...]` | `[...]` | 6 | Stores and consumes v. |
| `loc_storew_le.i` | `[A,...]` | `[A,...]` | 5 | Stores A in memory order and retains it. |
| `loc_storew_be.i` | `[A,...]` | `[A,...]` | 11 | Stores A in reverse element order and retains its original stack order. |

Word-load costs assume four overwrite slots already exist. To push a fresh word,
`padw loc_loadw_le.i` costs nine raw operations, excluding frame and invocation overhead.

## Cryptographic Operations

### Hashing and Merkle Trees

| Instruction | Stack Input | Stack Output | Cycles | Notes |
| --- | --- | --- | ---: | --- |
| `hash` | `[A,...]` | `[B,...]` | 18 | Generic `Eidos::hash_elements(A)`; the four-element message length is bound into the initial chaining word. |
| `compress` | `[BLOCK_LO,BLOCK_HI,CV,...]` | `[BLOCK_LO,BLOCK_HI,CV',...]` | 1 | Eidos compression preserves both block words and replaces only the chaining word. |
| `hdword` | `[A,B,...]` | `[C,...]` | 15 | Generic Eidos hash of the eight Felts in `A` followed by `B`. |
| `mtree_get` | `[d,i,R,...]` | `[V,R,...]` | 13 | Reads the node and verifies its Merkle opening against R. Includes the advice event. |
| `mtree_set` | `[d,i,R,V',...]` | `[V,R',...]` | 33 | Authenticates the old node V and updates its value to V', producing R'. Both tree versions remain available to the advice provider. Includes the advice event. |
| `mtree_merge` | `[L,R,...]` | `[M,...]` | 18 | Registers the ordered parent and computes its root using reserved Merkle-node framing, distinct from generic `hdword`. Does not check child-tree availability. |
| `mtree_verify` | `[V,d,i,R,...]` | `[V,d,i,R,...]` | 1 | Verifies the opening of V against R, preserving all inputs. Accepts `.err="invalid Merkle opening"` or a named diagnostic constant; the default error code is 0. |
| `crypto_stream` | `[K_CTR,counter,src,dst,remaining,...]` | `[K_CTR,counter+1,src+8,dst+16,remaining-1,...]` | 1 | Derives an Eidos XOF block, XORs it bytewise with eight plaintext Felts, and writes sixteen u32 ciphertext limbs. K_CTR is one word. |

`mtree_get`, `mtree_set`, and `mtree_verify` require `1 <= d <= 64`, an index valid at that
depth, and the required Merkle path. The index is interpreted as its canonical field-element
integer and need not fit in u32. A merged parent can be registered even when the provider has
no child preimages.

The one-operation `mtree_verify` count excludes Merkle-path chiplet work: each path level
adds a controller row, and updates traverse both the old and new paths. Identical compression
inputs share compression-trace blocks, but each path traversal still contributes controller
rows and runtime work.

For `crypto_stream`, source and destination must be word-aligned u32 addresses; the ranges
`[src,src+8)` and `[dst,dst+16)` must fit in memory and must not overlap. Counter and remaining
updates use field arithmetic. The caller must establish their intended integer bounds; the
instruction does not reject `remaining = 0`.

### Arithmetic Circuits and Polynomial Evaluation

All four instructions below emit one raw VM operation. Their chiplet work can contribute many
rows to the proof trace, so a one-operation count is not a constant proving-cost guarantee.

| Instruction | Stack Input | Stack Output | Cycles | Notes |
| --- | --- | --- | ---: | --- |
| `eval_circuit` | `[ptr,n_read,n_eval,...]` | Unchanged | 1 | Evaluates the memory-encoded arithmetic circuit and requires its output to be zero. The caller must authenticate the encoding when relying on a particular relation. |
| `horner_eval_base` | `[c0,c1,c2,c3,c4,c5,c6,c7,T,alpha_ptr,acc0,acc1,...]` | Same layout with acc0/acc1 replaced | 1 | Processes eight base-field coefficients in top-first order: repeatedly set `acc = acc*alpha+cj` for j = 0 through 7. |
| `horner_eval_ext` | `[s0_lo,s0_hi,s1_lo,s1_hi,s2_lo,s2_hi,s3_lo,s3_hi,T,alpha_ptr,acc0,acc1,...]` | Same layout with acc0/acc1 replaced | 1 | Processes four extension-field coefficients `sj = (sj_lo,sj_hi)` in top-pair-first order: repeatedly set `acc = acc*alpha+sj`. |
| `fri_ext2fold4` | See layout below | See layout below | 1 | Performs a four-way extension-field FRI fold and checks cross-layer consistency. |

For `eval_circuit`, `ptr` is word-aligned; `n_read` is a positive even count of extension-field
inputs/constants, and `n_eval` is a positive multiple of four counting base-field gate
encodings. The current processor requires `n_read+n_eval <= 32768`. Witness collection also
caps recorded invocations at 32 across contexts; untraced execution enforces the per-call wire
limit. These are processor resource limits, not new acceptance rules imposed by the circuit's
arithmetic relation.

In the Horner layouts, `T` denotes five unchanged Felts at positions 8 through 12. The
extension accumulator occupies positions 14 and 15, low coefficient first. The instruction
reads `alpha` from the word-aligned memory word `[alpha0,alpha1,0,0]` at `alpha_ptr` (position
13), checks its zero padding, and preserves every stack value except the accumulator. The
first coefficient on the stack is processed first and therefore has the highest degree in
that batch.

`fri_ext2fold4` has this top-first transition:

```text
Input:
[v0,v1,v2,v3,v4,v5,v6,v7, f_pos,coset,poe,pe0,pe1,a0,a1,layer_ptr, eptr,...]

Output:
[t0,t1,s0,s1,cf1,cf2,cf3,poe^2, layer_ptr+8,layer_ptr+8,poe^4,f_pos,ne0,ne1,layer_ptr+8,eptr,...]
```

The four input extension values `(v0,v1)` through `(v6,v7)` are in bit-reversed row order.
`coset` is the natural index in `0..=3`; its bit reversal selects the row value that must equal
the previous fold `(pe0,pe1)`. `poe` must be nonzero. The challenge is `(a0,a1)` and the new
fold is `(ne0,ne1)`, all extension pairs in low-coefficient-first order. The first eight output
Felts are degree-reduction scratch; callers should not treat them as additional fold outputs.
The instruction reduces stack depth by one, bringing `eptr` from input depth 16 to output depth
15. Pointer/power updates shown here are field arithmetic.

## Flow Control Operations

These costs count control rows separately from body operations, body/control framing, padding,
and any surrounding join nodes.

### Conditional Execution

```masm
if.true
    # true branch
else
    # false branch
end
```

`if.true` consumes a boolean condition, selecting the first branch for 1 and the second for 0.
`if.false` selects the first branch for 0; its branches are swapped during parsing, with no
extra `not` instruction. The `else` branch is optional. Execution rejects nonbinary conditions.
A conditional uses two control cycles (SPLIT and END), plus the selected body's cost.

An omitted `else` and accepted empty branches become a `nop` basic block, including its
operation and block-framing costs. Empty source branches are allowed when an `else` is
present; an empty `if` body without an `else` is a syntax error.

### Counter-Controlled Loops

```masm
repeat.COUNT
    # body
end
```

`COUNT` is an integer or named constant in `1..=1,000,000`. The assembler unrolls the body;
there is no runtime loop counter. The resulting body, joins, control structures, and padding
still contribute their normal costs.

### Condition-Controlled Loops

```masm
while.true
    # body; leave the next boolean condition on top
end
```

The initial condition is consumed before entering the body. A zero skips the body; a one
enters it. Each iteration then consumes the new condition left by the body, repeating on one
and exiting on zero. All checked conditions must be binary.

`while.true` lowers to an initial SPLIT guarding a native do-while LOOP. For `n >= 1` body
iterations it has `n+3` control cycles, excluding body and surrounding joins: two for the
outer conditional, one LOOP entry, and n tail REPEAT/END rows. Zero iterations use the outer
two control rows plus a `nop` basic block and its framing.

### Do-While Loops

```masm
do
    # nonempty body
while
    # nonempty condition computation; leave a boolean on top
end
```

The body and condition execute at least once. A native LOOP consumes the condition at the tail,
repeating for one and exiting for zero; nonbinary conditions fail. There is no initial SPLIT.
For n iterations, `n >= 1`, the control cost is `n+1`: one LOOP entry and n tail checks, plus
body/condition operations and framing.

## Procedure Invocation

Retained invocations resolve a **procedure key** under the execution's fixed environment root.
An implementation commitment is not a substitute for that key. Each retained invocation has
one entry and one return control row, plus the selected body's operations, local-frame work,
control nodes, and framing/padding. Local or bundled code is not implicitly inlined.

| Instruction | Stack / context effect | Invocation control cycles |
| --- | --- | --- |
| `exec.name` | Uses the callee's declared stack ABI in the same context, preserving access to its stack overflow, memory, and established principal. | 2 plus body |
| `inline.name` | Structurally expands a selected body at assembly time. Requires a local fixed body or an explicitly implementation-pinned import; Latest imports and inline cycles are rejected. The body's own local-frame work remains. | No retained invocation boundary; body costs remain |
| `call.name` | Passes the top 16 operand slots into a new isolated user-memory context, hiding caller overflow. Establishes the requested procedure key as principal. Return restores the caller's context, overflow, and principal; callee depth must be exactly 16. | 2 plus body |
| `syscall.name` | Passes the top 16 slots into the root memory context, hiding caller overflow and preserving the established principal. The binding's immediate parent namespace must be `Namespace::initial()`. Return requires depth 16 and restores caller state. | 2 plus body |
| `dynexec` | `[ptr,...]`: consumes a word-aligned u32 pointer, reads a procedure key from that memory word, then applies `exec` semantics. | 2 plus body |
| `dyncall` | Consumes the same kind of pointer, then applies `call` semantics to the top 16 slots remaining after that pop. | 2 plus body |

The dynamic instructions do not push a key or return address. See
[execution contexts](execution_contexts.md) for context, principal, and return details.

## Events

Event instructions are ordinary executable instructions, not debug-mode-erased decorators.
Immediate event IDs come from a typed declaration such as `const ID = event("name")` or an
inline expression such as `emit.event("name")`; numeric immediate IDs are not accepted.

| Instruction | Stack Input | Stack Output | Cycles | Notes |
| --- | --- | --- | ---: | --- |
| `emit.ID` / `emit.event("name")` | `[...]` | `[...]` | 3 | Emits the specified host event, lowering to Push(ID), Emit, Drop. The immediate is pushed directly, without scalar-push 0/1 specialization. |
| `emit` | `[event_id,...]` | `[event_id,...]` | 1 | Reads the event ID without consuming it and invokes its handler. System event names use the reserved `sys::` namespace. |
| `trace.ID` / `trace.event("name")` | `[...]` | `[...]` | 5 | Emits an optional read-only trace event: Push(ID), Push(sys_trace_event), Emit, Drop, Drop. Preserves the stack. |
| `trace` | `[trace_id,...]` | `[trace_id,...]` | 3 | Emits the optional read-only trace event for the top ID without consuming it: Push(sys_trace_event), Emit, Drop. |
| `log_deferred` | `[STMNT,...]` | `[ROOT_NEW,...]` | 1 | Folds the statement into the rolling deferred root as `Eidos::compress(DEFERRED_AND_INIT_CV, ROOT_PREV` followed by `STMNT)`. The statement must be registered and evaluate to TRUE. |

Trace handlers can inspect processor state but cannot mutate VM state or advice. An unhandled
optional trace is a no-op at the handler level; its emitted instructions still execute. Host
advice mutations produced by an ordinary event are untrusted until checked by the program.

## Debugging Procedures

These are ordinary `miden::core::debug` library procedures, not special MASM instructions.
They emit events and remain active regardless of assembly debug mode. Adding a call changes
the executed code, and procedures with inputs consume them. The counts below are **raw body
operations**, excluding retained-call entry/return, block framing, and padding.

| Procedure | Stack Input | Stack Output | Body operations | Notes |
| --- | --- | --- | ---: | --- |
| `print_stack` | `[...]` | `[...]` | 3 | Prints the operand stack. |
| `print_mem` | `[start,end,...]` | `[...]` | 5 | Prints current-context memory in `[start,end)`, capped at 1024 addresses. |
| `print_mem_addr` | `[addr,...]` | `[...]` | 8 | Prints one current-context memory cell. |
| `print_mem_all` | `[...]` | `[...]` | 3 | Lists initialized memory cells in the current context. |
| `print_adv_stack` | `[start,end,...]` | `[...]` | 5 | Prints an advice-stack range. |
| `print_adv_stack_all` | `[...]` | `[...]` | 7 | Prints the entire advice stack. |
| `print_adv_map_all` | `[...]` | `[...]` | 3 | Prints the advice map. |
| `print_adv_map_item` | `[KEY,...]` | `[...]` | 7 | Prints the payload under KEY, consuming that word. |

Default core-library handlers enable operand-stack and memory printing. Advice-print handlers
require host opt-in; hosts can replace or unregister handlers. Range procedures consume both
range arguments, and the map-item procedure consumes its key.
