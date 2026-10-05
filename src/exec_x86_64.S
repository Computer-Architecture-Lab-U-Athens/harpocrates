/* Context switch into and out of a sequence. AT&T syntax.
 * Offsets into struct harp_exec_state (harprun.h). */
#define ST_ENTRY      0
#define ST_HOST_RSP   8
#define ST_SEQ_RSP    16
#define ST_XSAVE_MASK 24
#define ST_MXCSR      32
#define ST_INSIDE     40
#define ST_CAP        48
#define CAP_GPR       (ST_CAP + 0)
#define CAP_RFLAGS    (ST_CAP + 128)
#define CAP_RIP       (ST_CAP + 136)
#define CAP_EXIT_KIND (ST_CAP + 144)

  .text
  .align 16
  .globl harp_run
  .type harp_run, @function
/* void harp_run(uint64_t entry): save host callee-saved state, load the baseline
 * sequence state (every x87/SSE/AVX/AVX-512 component in its architectural initial
 * configuration via xrstor64 from harp_init_image, zero GPRs, RFLAGS 0x202) and
 * jump to entry. Control comes back through harp_return. */
harp_run:
  pushq %rbp
  pushq %rbx
  pushq %r12
  pushq %r13
  pushq %r14
  pushq %r15
  movq %rdi, harp_state+ST_ENTRY(%rip)
  movq %rsp, harp_state+ST_HOST_RSP(%rip)
  movq $1, harp_state+ST_INSIDE(%rip)
  /* Sequence stack. */
  movq harp_state+ST_SEQ_RSP(%rip), %rsp
  movq %rsp, %rbp
  /* FP/vector baseline. xrstor64 with an all-zero XSTATE_BV header puts every
   * component in the mask into its initial configuration (x87 incl. ST0-7/MM0-7,
   * SSE, AVX, opmask, ZMM) and loads MXCSR from the image; fninit alone would leave
   * the x87 data registers. Without XSAVE, fxrstor64 loads the legacy image. */
  movq harp_state+ST_XSAVE_MASK(%rip), %rax
  testq %rax, %rax
  jz 1f
  movq %rax, %rdx
  shrq $32, %rdx
  xrstor64 harp_init_image(%rip)
  jmp 2f
1:
  fxrstor64 harp_init_image(%rip)
2:
  xorl %eax, %eax
  xorl %ebx, %ebx
  xorl %ecx, %ecx
  xorl %edx, %edx
  xorl %esi, %esi
  xorl %edi, %edi
  xorl %r8d, %r8d
  xorl %r9d, %r9d
  xorl %r10d, %r10d
  xorl %r11d, %r11d
  xorl %r12d, %r12d
  xorl %r13d, %r13d
  xorl %r14d, %r14d
  xorl %r15d, %r15d
  /* RFLAGS baseline, after the xors (which set ZF and PF); uses the sequence stack. */
  pushq $0x202
  popfq
  jmp *harp_state+ST_ENTRY(%rip)
  .size harp_run, .-harp_run

  .align 16
  .globl harp_exit_trampoline
  .type harp_exit_trampoline, @function
/* Reached by the jump appended after every sequence with the sequence's final
 * register state. Stores are RIP-relative and do not change RFLAGS. */
harp_exit_trampoline:
  movq %rax, harp_state+CAP_GPR+0(%rip)
  movq %rbx, harp_state+CAP_GPR+8(%rip)
  movq %rcx, harp_state+CAP_GPR+16(%rip)
  movq %rdx, harp_state+CAP_GPR+24(%rip)
  movq %rsi, harp_state+CAP_GPR+32(%rip)
  movq %rdi, harp_state+CAP_GPR+40(%rip)
  movq %rbp, harp_state+CAP_GPR+48(%rip)
  movq %rsp, harp_state+CAP_GPR+56(%rip)
  movq %r8,  harp_state+CAP_GPR+64(%rip)
  movq %r9,  harp_state+CAP_GPR+72(%rip)
  movq %r10, harp_state+CAP_GPR+80(%rip)
  movq %r11, harp_state+CAP_GPR+88(%rip)
  movq %r12, harp_state+CAP_GPR+96(%rip)
  movq %r13, harp_state+CAP_GPR+104(%rip)
  movq %r14, harp_state+CAP_GPR+112(%rip)
  movq %r15, harp_state+CAP_GPR+120(%rip)
  leaq harp_exit_stack_top(%rip), %rsp
  pushfq
  popq %rax
  movq %rax, harp_state+CAP_RFLAGS(%rip)
  movl $0, harp_state+CAP_EXIT_KIND(%rip)
  /* Vector and x87 state. harp_xsave_area was zeroed by the runner beforehand. */
  movq harp_state+ST_XSAVE_MASK(%rip), %rax
  testq %rax, %rax
  jz 3f
  movq %rax, %rdx
  shrq $32, %rdx
  xsave64 harp_xsave_area(%rip)
  jmp harp_return
3:
  fxsave64 harp_xsave_area(%rip)
  jmp harp_return
  .size harp_exit_trampoline, .-harp_exit_trampoline

  .align 16
  .globl harp_exit_from_signal
  .type harp_exit_from_signal, @function
/* The signal handler already copied registers into the capture and set the exit
 * kind; it resumes execution here with RSP on the exit stack. */
harp_exit_from_signal:
  jmp harp_return
  .size harp_exit_from_signal, .-harp_exit_from_signal

  .align 16
  .type harp_return, @function
harp_return:
  movq $0, harp_state+ST_INSIDE(%rip)
  /* Host ABI state: x87/MXCSR control words and DF must be sane on return. */
  fninit
  ldmxcsr harp_state+ST_MXCSR(%rip)
  cld
  movq harp_state+ST_HOST_RSP(%rip), %rsp
  popq %r15
  popq %r14
  popq %r13
  popq %r12
  popq %rbx
  popq %rbp
  ret
  .size harp_return, .-harp_return

  .bss
  .align 64
  .globl harp_xsave_area
harp_xsave_area:
  .zero 4096
  .align 64
  .globl harp_init_image
harp_init_image:
  .zero 4096
  .align 16
harp_exit_stack:
  .zero 65536
  .align 16
  .globl harp_exit_stack_top
harp_exit_stack_top:
  .zero 16

  .section .note.GNU-stack,"",@progbits
