---
title: "Execution Contexts"
sidebar_position: 3
---

## Execution contexts

Miden assembly program execution can span multiple isolated contexts. An execution context defines its own memory space which is not accessible from other execution contexts.

All programs start executing in a _root_ context. Thus, the main procedure of a program is always executed in the root context. To move execution into a different context, we can invoke a procedure using the `call` instruction. In fact, any time we invoke a procedure using the `call` instruction, the procedure is executed in a new context. We refer to all non-root contexts as _user contexts_.

While executing in a user context, we can request to execute a procedure in the root context via the `syscall` instruction. The invoked procedure must have an authenticated binding whose immediate parent namespace is the fixed, nonzero `N0 = Namespace::initial()`. The caller-authorized environment root determines these bindings; a compiled kernel export list does not authorize syscalls. Once the procedure returns, execution moves back to the user context from which it was invoked. The diagram below illustrates this graphically:

![context transitions](../../img/user_docs/assembly/execution_contexts/context_transitions.png)

### Procedure invocation semantics

As mentioned in the [previous section](./code_organization.md), procedures in Miden assembly can be invoked via five different instructions: `exec`, `call`, `syscall`, `dynexec`, and `dyncall`. Each runtime invocation uses a procedure key and authenticates its binding under the same fixed environment root. `call` and `dyncall` create user contexts and establish the requested procedure key as the principal. `syscall` requires the authenticated parent namespace to equal `N0`, enters the root context, and preserves the caller's principal. `exec` and `dynexec` preserve the current context and principal, as described below.

#### Invoking via `call`, `dyncall`, and `syscall` instructions

When a procedure is invoked via a `call`, `dyncall`, or a `syscall` instruction, the following happens:

- Execution moves into a different context. In case of the `call` and `dyncall` instructions, a new user context is created. In case of a `syscall` instruction, the execution moves back into the root context.
- All stack items beyond the 16th item get "hidden" from the invoked procedure. That is, from the standpoint of the invoked procedure, the initial stack depth is set to 16.
    - Note that for `dyncall`, the stack is shifted left by one element before being set to 16.

When the callee returns, the following happens:

- The execution context of the caller is restored
- If the original stack depth was greater than 16, those elements that were "hidden" during the call as described above, are restored. However, the stack depth must be _exactly_ 16 elements when the procedure returns, or this will fail and the VM will trap.

The manipulations of the stack depth described above have the following implications:

- The top 16 elements of the stack can be used to pass parameters and return values between the caller and the callee.
- Caller's stack beyond the top 16 elements is inaccessible to the callee, and thus, is guaranteed not to change as the result of the call.
    - As mentioned above, in the case of `dyncall`, the elements at indices 1 to 17 at the call site will be accessible to the callee (shifted to indices 0 to 16)
- At the end of its execution, the callee must ensure that stack depth is exactly 16. If this is difficult to ensure manually, the [`truncate_stack`](../core_lib/sys.md) procedure can be used to drop all elements from the stack except for the top 16.

#### Invoking via `exec` and `dynexec` instructions

The `exec` instruction can be thought of as the "normal" way of invoking procedures, i.e. it has semantics that would be familiar to anyone coming from a standard programming language, or that is familiar with procedure call instructions in a typical assembly language.

In Miden Assembly, `exec` executes a procedure in the same context as the caller, sharing its memory, operand stack, overflow, and frame memory pointer. `dynexec` has the same context and principal behavior with a dynamically supplied procedure key. Both are runtime keyed invocations: their bindings are authenticated even for local or bundled helpers. Bundling code does not inline it or freeze a Latest dependency's implementation.

Structural inlining requires an explicit `inline.<target>` instruction and an eligible fixed body. It is limited to local targets or imports with an explicit fixed-body pin; Latest targets and structural inline cycles are rejected. This is separate from runtime recursion through keyed invocations.

### Kernels

Kernel tooling places public executable exports at the canonical environment root, where their immediate parent namespace is `N0`. This includes public submodule exports and reexports, whose source aliases preserve the defining canonical procedure key. Root executable labels must be globally unique across composed kernel fragments. Private kernel helpers are placed beneath child `Env` namespaces; application homes remain explicit caller/tooling inputs.

The VM authorizes an actual `syscall` solely by authenticating the requested binding and checking that its immediate parent namespace equals the fixed `N0`. Every executable binding placed there is eligible, regardless of its source visibility or package kind. There is no additional syscall-export list or configurable kernel namespace. Environment construction must therefore reserve root bindings for kernel-safe entry points.

`List` and `Merkle` grouping preserve the inherited namespace, so root exports remain syscall-eligible at any physical depth beneath such nodes. An `Env` edge changes the namespace; a helper beneath a child `Env` is not eligible merely because an ancestor is at the root. This namespace placement does not isolate memory or change context, principal, or return conventions. Ordinary invocation modes and the execution entry may also use root exports.

A kernel can use the same internal and exported procedure declarations as a regular [library module](./code_organization.md#library-modules). Source module labels such as `$kernel`, imports, and visibility guide tooling and linking; they grant no execution authority. Kernel helpers may be invoked with `exec` under their authenticated keys while preserving the existing context and principal. Their homes need not use a particular textual prefix.

### Memory layout

As mentioned earlier, procedures executed within a given context can access memory only of that context. This is true for both memory reads and memory writes.

Address space of every context is the same: the smallest accessible address is $0$ and the largest accessible address is $2^{32} - 1$. Any code executed in a given context has access to its entire address space. However, by convention, we separate the memory into 2 distinct regions:

- The first $2^{31}$ addresses are assumed to be global memory, freely usable by programs.
- All addresses including and above $2^{31}$ are reserved for procedure locals (i.e., via the `exec` instruction).

> Note that address $2^{32} - 2$ is reserved by the VM to store the frame memory pointer.

![memory layout](../../img/user_docs/assembly/execution_contexts/mem_layout.png)

Writing directly into memory at an address including and above $2^{31}$ is not advisable. Instead, `loc_load`, `loc_store` and other similar dedicated instructions should be used to access procedure locals.

### Example

To better illustrate what happens as we execute procedures in different contexts, let's go over the following example.

This schematic source assumes explicit namespace bindings that place the public `baz` export at `N0` and the application entry, `foo`, and `bar` beneath an application `Env` namespace. The source names in `call.foo`, `call.bar`, `exec.bar`, and `syscall.baz` are aliases for those canonical procedure keys; their spelling does not choose a namespace or grant syscall authority.

```
kernel
--------------------
@locals(2)
pub proc baz
    <instructions>
    caller
    <instructions>
end

program
--------------------
@locals(1)
proc bar
    <instructions>
    syscall.baz
    <instructions>
end

@locals(3)
proc foo
    <instructions>
    call.bar
    <instructions>
    exec.bar
    <instructions>
end

begin
    <instructions>
    call.foo
    <instructions>
end
```

Execution of the above program proceeds as follows:

1. The VM starts executing instructions immediately following the `begin` statement. These instructions are executed in the _root_ context (let's call this context `ctx0`).
2. When `call.foo` is executed, a new context is created (`ctx1`). Memory in this context is isolated from `ctx0`. Additionally, any elements on the stack beyond the top 16 are hidden from `foo`.
3. Instructions executed inside `foo` can access memory of `ctx1` only. The address of the first procedure local in `foo` (e.g., accessed via `loc_load.0`) is $2^{31}$.
4. When `call.bar` is executed, a new context is created (`ctx2`). The stack depth is set to 16 again, and any instruction executed in this context can access memory of `ctx2` only. The first procedure local of `bar` is also located at address $2^{31}$.
5. When `syscall.baz` is executed, the execution moves back into the root context. That is, instructions executed inside `baz` have access to the memory of `ctx0`. The first procedure local of `baz` is located at address $2^{31}$. When `baz` starts executing, the stack depth is again set to 16.
6. When `caller` is executed inside `baz`, the first 4 elements of the stack are populated with the procedure key of `bar`, the principal established by `call.bar` and preserved by `syscall.baz`.
7. Once `baz` returns, execution moves back to `ctx2`, and then, when `bar` returns, execution moves back to `ctx1`. We assume that instructions executed right before each procedure returns ensure that the stack depth is exactly 16 right before procedure's end.
8. Next, when `exec.bar` is executed, `bar` is executed again, but this time it is executed in the same context as `foo`. Thus, it can access memory of `ctx1`. Moreover, the stack depth is not changed, and thus, `bar` can access the entire stack of `foo`. Lastly, this first procedure local of `bar` now will be at address $2^{31} + 3$ (since the first 3 locals in this context are reserved for `foo`).
9. When `syscall.baz` is executed the second time, execution moves into the root context again. Now `caller` exposes the procedure key of `foo`: `exec.bar` preserved the principal established by `call.foo`, and `syscall.baz` preserves it as well.
10. Finally, when `baz` returns, execution moves back to `ctx1`, and then as `bar` and `foo` return, back to `ctx0`, and the program terminates.
