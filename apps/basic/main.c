#include <stdio.h>

#include "wrapper.h"

#if __GCC__ >= 12
#define vmgexit "vmgexit"
#else
#define vmgexit "rep; vmmcall"
#endif

static __inline long vmgexit_syscall(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
	unsigned long ret;
	register long r10 __asm__("r10") = a4;
	register long r8 __asm__("r8") = a5;
	register long r9 __asm__("r9") = a6;
	__syscall_wrapper(__volatile__(vmgexit : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
														 "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory"));
	return ret;
}

typedef long (*syscall_fn_t)(long, long, long, long, long, long, long);

static syscall_fn_t next_sys_call = NULL;

static long hook_function(long a1, long a2, long a3,
			  long a4, long a5, long a6,
			  long a7)
{
	// 根据当前是出于ring-0还是ring-3，选择不同的转发方式
	unsigned short cs;
	__asm__ __volatile__("movw %%cs, %0" : "=r"(cs));
	if ((cs & 0x3) == 0) {
		// ring-0
		return vmgexit_syscall(a1, a2, a3, a4, a5, a6, a7);
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

int __hook_init(long placeholder __attribute__((unused)),
		void *sys_call_hook_ptr)
{
	printf("output from __hook_init: we can do some init work here\n");

	next_sys_call = *((syscall_fn_t *) sys_call_hook_ptr);
	*((syscall_fn_t *) sys_call_hook_ptr) = hook_function;

	return 0;
}
