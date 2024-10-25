#ifndef _X86_64_GHCB_H
#define _X86_64_GHCB_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

// Common types
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

static inline bool test_bit(int nr, const unsigned long *addr) {
	return 1UL & (addr[nr >> 6] >> (nr & 63)) ? true : false;
}

static inline void __set_bit(int nr, unsigned long *addr) {
	addr[nr >> 6] |= 1UL << (nr & 63);
}

// GHCB MSR Protocol
#define GHCB_MSR 0xc0010130

/// 0xfff
#define GHCB_MSR_INFO_MASK 0xfff

#define GHCB_MSR_INFO(x) ((x) & GHCB_MSR_INFO_MASK)

#define GHCB_MSR_DATA(x) ((x) & ~GHCB_MSR_INFO_MASK)

/* GHCB Run at VMPL Request/Response */
/// 0x16
#define GHCB_MSR_VMPL_REQ 0x016
#define GHCB_MSR_VMPL_REQ_LEVEL(x) ((x) | GHCB_MSR_VMPL_REQ)
/// 0x17
#define GHCB_MSR_VMPL_RES 0x017
#define GHCB_MSR_VMPL_RESP_VAL(v) (v >> 32)

#define GHCB_MSR_VMPL_RESP 0x17
#define GHCB_RESP_CODE(x) GHCB_MSR_INFO(x)

// Read MSR
static inline unsigned long __rdmsr(unsigned int msr) {
    unsigned int lo;
    unsigned int hi;

    __asm__ __volatile__("rdmsr"
                         : "=a"(lo), "=d"(hi)
                         : "c"(msr)
                         : "memory");

    return ((unsigned long)hi << 32) | lo;
}

// Write to MSR a given value
static inline void __wrmsr(unsigned int msr, unsigned long value) {
    unsigned int lo = value;
    unsigned int hi = value >> 32;

    __asm__ __volatile__("wrmsr"
                         :
                         : "c"(msr), "a"(lo), "d"(hi)
                         : "memory");
}

// GHCB Save Area

struct ghcb_save_area {
	uint8_t reserved_0x0[0x0390];
	uint64_t sw_exit_code;
	uint64_t sw_exit_info_1;
	uint64_t sw_exit_info_2;
	uint64_t sw_scratch;
	uint8_t reserved_0x3b0[0x40];
	uint8_t valid_bitmap[0x10];
	uint64_t x87_state_gpa;
} __attribute__((packed));

#define GHCB_SHARED_BUF_SIZE	2032

struct ghcb {
	struct ghcb_save_area save;
	uint8_t reserved_save[2048 - sizeof(struct ghcb_save_area)];

	uint8_t shared_buffer[GHCB_SHARED_BUF_SIZE];

	uint8_t reserved_0xff0[10];
	uint16_t protocol_version;	/* negotiated SEV-ES/GHCB protocol version */
	uint32_t ghcb_usage;
} __attribute__((packed));

/* STATIC ASSERTS */
#define STATIC_ASSERT(value, offset) \
	_Static_assert(offsetof(struct ghcb, value) == offset, "GHCB " #value " offset mismatch")

STATIC_ASSERT(save.sw_exit_code, 0x0390);
STATIC_ASSERT(save.sw_exit_info_1, 0x0398);
STATIC_ASSERT(save.sw_exit_info_2, 0x03a0);
STATIC_ASSERT(save.sw_scratch, 0x03a8);
STATIC_ASSERT(save.valid_bitmap, 0x03f0);
STATIC_ASSERT(save.x87_state_gpa, 0x0400);
STATIC_ASSERT(shared_buffer, 0x0800);
STATIC_ASSERT(protocol_version, 0x0ffa);
STATIC_ASSERT(ghcb_usage, 0x0ffc);

/* GHCB Accessor functions */

#define GHCB_BITMAP_IDX(field)							\
	(offsetof(struct ghcb_save_area, field) / sizeof(uint64_t))

#define DEFINE_GHCB_ACCESSORS(field)						\
	static inline bool ghcb_##field##_is_valid(const struct ghcb *ghcb) \
	{									\
		return test_bit(GHCB_BITMAP_IDX(field),				\
				(unsigned long *)&ghcb->save.valid_bitmap[0]);	\
	}									\
										\
	static inline uint64_t ghcb_get_##field(struct ghcb *ghcb)		\
	{									\
		return ghcb->save.field;					\
	}									\
										\
	static inline uint64_t ghcb_get_##field##_if_valid(struct ghcb *ghcb) \
	{									\
		return ghcb_##field##_is_valid(ghcb) ? ghcb->save.field : 0;	\
	}									\
										\
	static inline void ghcb_set_##field(struct ghcb *ghcb, uint64_t value) \
	{									\
		__set_bit(GHCB_BITMAP_IDX(field),				\
			  (unsigned long *)&ghcb->save.valid_bitmap[0]);		\
		ghcb->save.field = value;					\
	}

DEFINE_GHCB_ACCESSORS(sw_exit_code)
DEFINE_GHCB_ACCESSORS(sw_exit_info_1)
DEFINE_GHCB_ACCESSORS(sw_exit_info_2)

/**
 * lower_32_bits - return bits 0-31 of a number
 * @n: the number we're accessing
 */
#define lower_32_bits(n) ((unsigned int)((n) & 0xffffffff))

#define GHCB_PROTOCOL_MIN	1ULL
#define GHCB_PROTOCOL_MAX	2ULL

#define GHCB_DEFAULT_USAGE	0ULL

#define SVM_VMGEXIT_SNP_RUN_VMPL		0x80000018

#endif