	.file	"bus.c"
	.section	.rodata
.LC0:
	.string	"/tmp/y86-shm"
.LC1:
	.string	"bus.c"
.LC2:
	.string	"fd != -1"
.LC3:
	.string	"shared != ((void *) -1)"
.LC4:
	.string	"%d\n"
	.text
	.globl	main
	.type	main, @function
main:
.LFB0:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movl	$0, %edx
	movl	$2, %esi
	movl	$.LC0, %edi
	movl	$0, %eax
	call	open
	movl	%eax, -12(%rbp)
	cmpl	$-1, -12(%rbp)
	jne	.L2
	movl	$__PRETTY_FUNCTION__.2516, %ecx
	movl	$9, %edx
	movl	$.LC1, %esi
	movl	$.LC2, %edi
	call	__assert_fail
.L2:
	movl	-12(%rbp), %eax
	movl	$0, %r9d
	movl	%eax, %r8d
	movl	$33, %ecx
	movl	$3, %edx
	movl	$4096, %esi
	movl	$0, %edi
	call	mmap
	movq	%rax, -8(%rbp)
	cmpq	$-1, -8(%rbp)
	jne	.L3
	movl	$__PRETTY_FUNCTION__.2516, %ecx
	movl	$12, %edx
	movl	$.LC1, %esi
	movl	$.LC3, %edi
	call	__assert_fail
.L3:
	movl	$0, -16(%rbp)
.L5:
	movq	-8(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	cmpl	-16(%rbp), %eax
	je	.L4
	movq	-8(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	movl	%eax, -16(%rbp)
	movl	-16(%rbp), %eax
	movl	%eax, %esi
	movl	$.LC4, %edi
	movl	$0, %eax
	call	printf
.L4:
	jmp	.L5
	.cfi_endproc
.LFE0:
	.size	main, .-main
	.section	.rodata
	.type	__PRETTY_FUNCTION__.2516, @object
	.size	__PRETTY_FUNCTION__.2516, 5
__PRETTY_FUNCTION__.2516:
	.string	"main"
	.ident	"GCC: (Ubuntu 4.9.1-16ubuntu6) 4.9.1"
	.section	.note.GNU-stack,"",@progbits
