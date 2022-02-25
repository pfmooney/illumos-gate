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



/* VMM Data Identifiers */


/*
 * VDC_REGISTER:
 */

/*
 * VDC_MSR:
 *
 * Use MSR identifiers directly
 */

/*
 * VDC_FPU:
 *
 * Unimplemented for now.  Use VM_GET_FPU/VM_SET_FPU ioctls.
 */

/*
 * VDC_LAPIC:
 *
 * 0x000-0x400: (LAPIC MMIO register address)
 * 0x1000: ICR Timer deadline (hrtime)
 * 0x1001: ESR pending
 * 0x1002: APIC base MSR
 */


/*
 * VDC_VMM_ARCH:
 *
 */

/*
 * VDC_IOAPIC:
 *
 * - 0x000 + pin: register for pin
 * - 0x100 + pin: interrupt level for pin
 * - 0x200: IOAPIC ID
 * - 0x201: IO register selector
 */

#define	VDI_IOAPIC_REG(pin)	((pin) & 0xff)
#define	VDI_IOAPIC_LEVEL(pin)	(((pin) & 0xff) + 0x100)

#define	VDI_IOAPIC_ID		0x200
#define	VDI_IOAPIC_IOREGSEL	0x201

/*
 * VDC_ATPIT:
 *
 * - 0x0: counter value
 * - 0x1: CR register
 * - 0x2: OL register
 * - 0x3: status register
 * - 0x4: mode
 * - 0x5: status bits
 *   - 0b00001 status latched
 *   - 0b00010 output latched
 *   - 0b00100 control register sel
 *   - 0b01000 output latch sel
 *   - 0b10000 free-running timer
 * - 0x6: time when counter was loaded (hrtime_t)
 * - 0x7: target time
 *
 * Ident = (channel << 4) + register
 * For example 0x12 is CR register for channel 1
 */

#define	VDI_ATPIT_REG(chan, reg)	((((chan) & 0x3) << 4) + ((reg) & 0x7))
#define	VDI_ATPIT_COUNTER		0x0
#define	VDI_ATPIT_REG_CR		0x1
#define	VDI_ATPIT_REG_OL		0x2
#define	VDI_ATPIT_REG_STATUS		0x3
#define	VDI_ATPIT_MODE			0x4
#define	VDI_ATPIT_STATUS		0x5
#define	VDI_ATPIT_TIME_LOADED		0x6
#define	VDI_ATPIT_TIME_TARGET		0x7

/*
 * VDC_ATPIC:
 *
 * 0x0X prefix for chip 0, 0x1X prefix for chip 1
 *
 * - 0x0: chip state
 * - 0x1: status bits
 *   - 0b00000001 ready
 *   - 0b00000010 auto EOI
 *   - 0b00000100 poll
 *   - 0b00001000 rotate
 *   - 0b00010000 special full nested
 *   - 0b00100000 read isr next
 *   - 0b01000000 intr raised
 *   - 0b10000000 special mask mode
 * - 0x2: IRR
 * - 0x3: ISR
 * - 0x4: IMR
 * - 0x5: IRQ base
 * - 0x6: lowest prio IRQ
 * - 0x7: ELC mode bits
 * - 0x8 - 0xf: pin levels
 */
#define	VDI_ATPIC_REG(chip, reg)	((((chip) & 0x1) << 4) + ((reg) & 0xf))
#define	VDI_ATPIC_STATE			0x0
#define	VDI_ATPIC_STATUS		0x1
#define	VDI_ATPIC_IRR			0x2
#define	VDI_ATPIC_ISR			0x3
#define	VDI_ATPIC_IMR			0x4
#define	VDI_ATPIC_IRQ_BASE		0x5
#define	VDI_ATPIC_LOW_PRIO		0x6
#define	VDI_ATPIC_ELC			0x7
#define	VDI_ATPIC_LEVEL(pin)		(((pin) & 0x7) + 0x8)

/*
 * VDC_HPET:
 *
 * For each (currently 8) timer, using (timer << 4) prefix:
 * - 0x0: Configuration register
 * - 0x1: MSI register
 * - 0x2: Comparator value
 * - 0x3: Comparator rate
 * - 0x4: Timer base (hrtime)
 *
 * Ident = (timer << 4) + register
 *
 * - 0x100: Device configuration register
 * - 0x101: ISR
 * - 0x102: counter base
 * - 0x103: Timer base (hrtime)
 */
#define	VDI_HPET_TMR_REG(tmr, reg)	((((tmr) & 0xf) << 4) + ((reg) & 0x7))
#define	VDI_HPET_TMR_CFG		0x0
#define	VDI_HPET_TMR_MSI		0x1
#define	VDI_HPET_TMR_COMPVAL		0x2
#define	VDI_HPET_TMR_COMPRATE		0x3
#define	VDI_HPET_TMR_TIME_BASE		0x4

#define	VDI_HPET_DEV_CFG		0x100
#define	VDI_HPET_ISR			0x101
#define	VDI_HPET_COUNTER_BASE		0x102
#define	VDI_HPET_TIME_BASE		0x103

/*
 * VDC_PM_TIMER:
 * - 0x0: Timer base (hrtime)
 * - 0x1: Base value
 * - 0x2: IO port (read-only)
 */

#define	VDI_PM_TIMER_TIME_BASE		0x0
#define	VDI_PM_TIMER_VAL_BASE		0x1
#define	VDI_PM_TIMER_IOPORT		0x2

/*
 * VDC_RTC:
 *
 * 0x0-0x7f: byte-wise access to RTC struct
 * 0x80-0ff: 8-byte-wide access to RTC struct
 * 0x100: RTC register address
 * 0x101: Time base (hrtime)
 * 0x102: RTC time (hrtime)
 */

#define	VDI_RTC_BYTE_WISE(off)	((off) & 0x7f)
#define	VDI_RTC_QWORD_WISE(off)	(((off) & 0x78) + 0x80)

#define	VDI_RTC_REG_ADDRESS	0x100
#define	VDI_RTC_TIME_BASE	0x101
#define	VDI_RTC_TIME_RTC	0x102

#endif /* _VMM_DATA_H_ */
