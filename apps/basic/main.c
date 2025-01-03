#include <stdio.h>

#include "wrapper.h"

typedef long (*syscall_fn_t)(long, long, long, long, long, long, long);

static syscall_fn_t next_sys_call = NULL;

static long hook_function(long a1, long a2, long a3,
			  long a4, long a5, long a6,
			  long a7)
{
#if DEBUG
	printf("output from hook_function: a1: %lx, a2: %lx, a3: %lx, a4: %lx, a5: %lx, a6: %lx, a7: %lx\n", a1, a2, a3, a4, a5, a6, a7);
#endif
	// 根据当前是出于ring-0还是ring-3，选择不同的转发方式
	if (is_ring0())
		return vmgexit_syscall(a1, a2, a3, a4, a5, a6, a7);

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
