/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/* This file is dual-licensed; see usr/src/contrib/bhyve/LICENSE */

/*
 * Copyright 2021 Oxide Computer Company
 */

#ifndef _VMM_DATA_H_
#define	_VMM_DATA_H_

/* VMM Data Classes */
#define	VDC_META	0	/* Meta information about data system */
#define	VDC_VERSION	1	/* Version information for each data class */

/* Classes bearing per-CPU data */
#define	VDC_REGISTER	2	/* Registers (GPR, segment, etc) */
#define	VDC_MSR		3	/* Model-specific registers */
#define	VDC_FPU		4	/* FPU (and associated SIMD) */
#define	VDC_LAPIC	5	/* Local APIC */
#define	VDC_VMM_ARCH	6	/* Arch-specific VMM state (VMX/SVM) */

/* Classes for system-wide devices */
#define	VDC_IOAPIC	7	/* bhyve IO-APIC */
#define	VDC_ATPIT	8	/* i8254 PIT */
#define	VDC_ATPIC	9	/* i8259 PIC */
#define	VDC_HPET	10	/* HPET */
#define	VDC_PM_TIMER	11	/* ACPI Power Management Timer */
#define	VDC_RTC		12	/* IBM PC Real Time Clock */

/* Indicates top of VMM Data Class range, updated as classes are added */
#define	VDC_MAX		(VDC_RTC + 1)


typedef struct vmm_data_item {
	uint16_t vdi_class;
	uint16_t _pad;
	uint32_t vdi_ident;
} vmm_data_item_t;

#endif /* _VMM_DATA_H_ */
