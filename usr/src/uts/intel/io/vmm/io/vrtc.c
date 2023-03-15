/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2014, Neel Natu (neel@freebsd.org)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright 2018 Joyent, Inc.
 * Copyright 2023 Oxide Computer Company
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/clock.h>
#include <sys/sysctl.h>

#include <machine/vmm.h>

#include <isa/rtc.h>

#include "vatpic.h"
#include "vioapic.h"
#include "vrtc.h"

/*
 * Virtual RTC: Fashioned after the MC146818
 *
 * Current limitations:
 * - Clock divider will only run at 32768Hz (not 1.x or 4.x MHz)
 * - Date-times prior to 1970-01-01 are not supported
 * - If date-time held in CMOS is not valid (such as a nonsensical month/day)
 *   then updates to the time (hours/minutes/seconds) will not occur, even if
 *   they are enabled through the divider and flags.
 */

/* Register layout of the RTC */
struct rtcdev {
	uint8_t	sec;
	uint8_t	alarm_sec;
	uint8_t	min;
	uint8_t	alarm_min;
	uint8_t	hour;
	uint8_t	alarm_hour;
	uint8_t	day_of_week;
	uint8_t	day_of_month;
	uint8_t	month;
	uint8_t	year;
	uint8_t	reg_a;
	uint8_t	reg_b;
	uint8_t	reg_c;
	uint8_t	reg_d;
	uint8_t	nvram[36];
	uint8_t	century;
	uint8_t	nvram2[128 - 51];
} __packed;
CTASSERT(sizeof (struct rtcdev) == 128);
CTASSERT(offsetof(struct rtcdev, century) == RTC_CENTURY);

struct vrtc {
	struct vm	*vm;
	kmutex_t	lock;
	struct callout	callout;

	/*
	 * Address within the RTC to access when reading/writing from the data
	 * IO port.
	 */
	uint8_t		addr;

	/*
	 * Time base for RTC functionality driven from the output of the
	 * (emulated) divider.  Holds the hrtime at the edge of the last update
	 * to seconds, be that an "official" update of the running RTC, the
	 * divider being enabled by the guest (and thus implying a start 500ms
	 * earlier), or the time being set by a userspace consumer.
	 */
	hrtime_t	base_clock;

	/*
	 * Time for most recent periodic-timer-driven event.  Should be kept in
	 * phase with base_clock as it relates to edge boundaries of seconds.
	 */
	hrtime_t	last_period;

	/*
	 * (UNIX) Time at the last base_clock reading.
	 *
	 * If an invalid date/time is specified in the RTC fields, this will
	 * hold VRTC_BROKEN_TIME to indicate to the rest of the vRTC logic that
	 * further updates will not occur on divider ticks (until the RTC fields
	 * are updated to hold a valid date/time).
	 */
	time_t		base_rtctime;

	struct rtcdev	rtcdev;
};

#define	VRTC_LOCK(vrtc)		mutex_enter(&((vrtc)->lock))
#define	VRTC_UNLOCK(vrtc)	mutex_exit(&((vrtc)->lock))
#define	VRTC_LOCKED(vrtc)	MUTEX_HELD(&((vrtc)->lock))

/*
 * RTC time is considered "broken" if:
 * - RTC updates are halted by the guest
 * - RTC date/time fields have invalid values
 */
#define	VRTC_BROKEN_TIME	((time_t)-1)

#define	RTC_IRQ			8

#define	RTCSA_DIVIDER_MASK	0x70
#define	RTCSA_DIVIDER_32K	0x20
#define	RTCSA_PERIOD_MASK	0x0f
#define	RTCSB_BIN		0x04
#define	RTCSB_INTR_MASK		(RTCSB_UINTR | RTCSB_AINTR | RTCSB_PINTR)
#define	RTCSC_MASK	(RTCIR_UPDATE | RTCIR_ALARM | RTCIR_PERIOD | RTCIR_INT)

#define	ROUNDDOWN(x,y)	(((x)/(y))*(y))

static void vrtc_regc_update(struct vrtc *, uint8_t);
static void vrtc_callout_reschedule(struct vrtc *);

static __inline bool
rtc_halted(const struct vrtc *vrtc)
{
	return ((vrtc->rtcdev.reg_b & RTCSB_HALT) != 0);
}

static __inline bool
rega_divider_en(uint8_t rega)
{
	/*
	 * The RTC is counting only when dividers are not held in reset.
	 */
	return ((rega & RTCSA_DIVIDER_MASK) == RTCSA_DIVIDER_32K);
}

static __inline hrtime_t
rega_period(uint8_t rega)
{
	const uint_t sel = rega & RTCSA_PERIOD_MASK;
	const hrtime_t rate_period[16] = {
		0,
		NANOSEC / 256,
		NANOSEC / 128,
		NANOSEC / 8192,
		NANOSEC / 4096,
		NANOSEC / 2048,
		NANOSEC / 1024,
		NANOSEC / 512,
		NANOSEC / 256,
		NANOSEC / 128,
		NANOSEC / 64,
		NANOSEC / 32,
		NANOSEC / 16,
		NANOSEC / 8,
		NANOSEC / 4,
		NANOSEC / 2,
	};

	return (rate_period[sel]);
}

static __inline bool
rtc_update_enabled(const struct vrtc *vrtc)
{
	/*
	 * RTC date/time can be updated only if:
	 * - divider is not held in reset
	 * - guest has not disabled updates
	 * - the date/time fields have valid contents
	 */
	if (!rega_divider_en(vrtc->rtcdev.reg_a))
		return (false);

	if (rtc_halted(vrtc))
		return (false);

	if (vrtc->base_rtctime == VRTC_BROKEN_TIME)
		return (false);

	return (true);
}

/*
 * Calculate the current time held by the RTC.  If the RTC is running (divider
 * enabled, and updates not halted) then this will account for any time has
 * passed since the last update.
 */
static time_t
vrtc_curtime(struct vrtc *vrtc, hrtime_t *basep, hrtime_t *phasep)
{
	time_t t = vrtc->base_rtctime;
	hrtime_t base = vrtc->base_clock;
	hrtime_t phase = 0;

	ASSERT(VRTC_LOCKED(vrtc));

	if (rtc_update_enabled(vrtc)) {
		const hrtime_t delta = gethrtime() - vrtc->base_clock;
		const time_t sec = delta / NANOSEC;

		ASSERT3S(delta, >=, 0);

		t += sec;
		base += sec * NANOSEC;
		phase = delta % NANOSEC;
	}
	if (basep != NULL) {
		*basep = base;
	}
	if (phasep != NULL) {
		*phasep = phase;
	}
	return (t);
}

/* Store a value in the RTC CMOS, converting to BCD if necessary */
static __inline uint8_t
rtcset(struct rtcdev *rtc, uint8_t val)
{
	const uint8_t bin2bcd_data[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
		0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
		0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99
	};

	ASSERT3U(val, <, 100);

	return ((rtc->reg_b & RTCSB_BIN) ? val : bin2bcd_data[val]);
}

/*
 * Write the date/time fields in the CMOS with the date represented by the
 * internal RTC time (base_rtctime).  If the time is not valid, or updates of
 * the RTC are disabled via register configuration (without force_update
 * override), then the CMOS contents will not be changed.
 */
static void
vrtc_time_to_cmos(struct vrtc *vrtc, bool force_update)
{
	struct rtcdev *rtc = &vrtc->rtcdev;
	struct timespec ts = {
		.tv_sec = vrtc->base_rtctime,
		.tv_nsec = 0,
	};

	ASSERT(VRTC_LOCKED(vrtc));

	if (vrtc->base_rtctime < 0) {
		ASSERT3S(vrtc->base_rtctime, ==, VRTC_BROKEN_TIME);
		return;
	}

	/*
	 * If the RTC is halted then the guest has "ownership" of the
	 * date/time fields. Don't update the RTC date/time fields in
	 * this case (unless forced).
	 */
	if (rtc_halted(vrtc) && !force_update) {
		return;
	}

	struct clocktime ct;
	clock_ts_to_ct(&ts, &ct);

	ASSERT(ct.sec >= 0 && ct.sec <= 59);
	ASSERT(ct.min >= 0 && ct.min <= 59);
	ASSERT(ct.hour >= 0 && ct.hour <= 23);
	ASSERT(ct.dow >= 0 && ct.dow <= 6);
	ASSERT(ct.day >= 1 && ct.day <= 31);
	ASSERT(ct.mon >= 1 && ct.mon <= 12);
	ASSERT(ct.year >= POSIX_BASE_YEAR);

	rtc->sec = rtcset(rtc, ct.sec);
	rtc->min = rtcset(rtc, ct.min);

	int hour;
	if (rtc->reg_b & RTCSB_24HR) {
		hour = ct.hour;
	} else {
		/*
		 * Convert to the 12-hour format.
		 */
		switch (ct.hour) {
		case 0:			/* 12 AM */
		case 12:		/* 12 PM */
			hour = 12;
			break;
		default:
			/*
			 * The remaining 'ct.hour' values are interpreted as:
			 * [1  - 11] ->  1 - 11 AM
			 * [13 - 23] ->  1 - 11 PM
			 */
			hour = ct.hour % 12;
			break;
		}
	}

	rtc->hour = rtcset(rtc, hour);

	if ((rtc->reg_b & RTCSB_24HR) == 0 && ct.hour >= 12)
		rtc->hour |= 0x80;	    /* set MSB to indicate PM */

	rtc->day_of_week = rtcset(rtc, ct.dow + 1);
	rtc->day_of_month = rtcset(rtc, ct.day);
	rtc->month = rtcset(rtc, ct.mon);
	rtc->year = rtcset(rtc, ct.year % 100);
	rtc->century = rtcset(rtc, ct.year / 100);
}

/* Read a value from the RTC CMOS, converting from BCD if necessary */
static int
rtcget(struct rtcdev *rtc, int val, int *retval)
{
	uint8_t upper, lower;

	if (rtc->reg_b & RTCSB_BIN) {
		*retval = val;
		return (0);
	}

	lower = val & 0xf;
	upper = (val >> 4) & 0xf;

	if (lower > 9 || upper > 9)
		return (-1);

	*retval = upper * 10 + lower;
	return (0);
}

/*
 * Read the date/time fields from the CMOS and attempt to convert it to a valid
 * UNIX timestamp.  VRTC_BROKEN_TIME will be emitted if those fields represent
 * an invalid date.
 *
 * The day-of-week field is ignored for the purposes of validation since certain
 * guests do not make use of it.
 */
static time_t
vrtc_cmos_to_secs(struct vrtc *vrtc)
{
	struct clocktime ct;
	struct timespec ts;
	struct rtcdev *rtc;
	int century, error, hour, pm, year;

	ASSERT(VRTC_LOCKED(vrtc));

	rtc = &vrtc->rtcdev;

	bzero(&ct, sizeof (struct clocktime));

	error = rtcget(rtc, rtc->sec, &ct.sec);
	if (error || ct.sec < 0 || ct.sec > 59) {
		/* invalid RTC seconds */
		goto fail;
	}

	error = rtcget(rtc, rtc->min, &ct.min);
	if (error || ct.min < 0 || ct.min > 59) {
		/* invalid RTC minutes */
		goto fail;
	}

	pm = 0;
	hour = rtc->hour;
	if ((rtc->reg_b & RTCSB_24HR) == 0) {
		if (hour & 0x80) {
			hour &= ~0x80;
			pm = 1;
		}
	}
	error = rtcget(rtc, hour, &ct.hour);
	if ((rtc->reg_b & RTCSB_24HR) == 0) {
		if (ct.hour >= 1 && ct.hour <= 12) {
			/*
			 * Convert from 12-hour format to internal 24-hour
			 * representation as follows:
			 *
			 *    12-hour format		ct.hour
			 *	12	AM		0
			 *	1 - 11	AM		1 - 11
			 *	12	PM		12
			 *	1 - 11	PM		13 - 23
			 */
			if (ct.hour == 12)
				ct.hour = 0;
			if (pm)
				ct.hour += 12;
		} else {
			/* invalid RTC 12-hour format */
			goto fail;
		}
	}

	if (error || ct.hour < 0 || ct.hour > 23) {
		/* invalid RTC hour */
		goto fail;
	}

	/*
	 * Ignore 'rtc->dow' because some guests like Linux don't bother
	 * setting it at all while others like OpenBSD/i386 set it incorrectly.
	 *
	 * clock_ct_to_ts() does not depend on 'ct.dow' anyways so ignore it.
	 */
	ct.dow = -1;

	error = rtcget(rtc, rtc->day_of_month, &ct.day);
	if (error || ct.day < 1 || ct.day > 31) {
		/* invalid RTC mday */
		goto fail;
	}

	error = rtcget(rtc, rtc->month, &ct.mon);
	if (error || ct.mon < 1 || ct.mon > 12) {
		/* invalid RTC month */
		goto fail;
	}

	error = rtcget(rtc, rtc->year, &year);
	if (error || year < 0 || year > 99) {
		/* invalid RTC year */
		goto fail;
	}

	error = rtcget(rtc, rtc->century, &century);
	ct.year = century * 100 + year;
	if (error || ct.year < POSIX_BASE_YEAR) {
		/* invalid RTC century */
		goto fail;
	}

	error = clock_ct_to_ts(&ct, &ts);
	if (error || ts.tv_sec < 0) {
		/* invalid RTC clocktime */
		goto fail;
	}
	return (ts.tv_sec);		/* success */
fail:
	/*
	 * Stop updating the RTC if the date/time fields programmed by
	 * the guest are invalid.
	 */
	return (VRTC_BROKEN_TIME);
}

static void
vrtc_periodic_update(struct vrtc *vrtc)
{
	struct rtcdev *rtc = &vrtc->rtcdev;

	ASSERT(VRTC_LOCKED(vrtc));

	/*
	 * If the divider is disabled, or periodic interrupts are not
	 * configured, then no further work is required.
	 */
	const hrtime_t period = rega_period(rtc->reg_a);
	if (!rega_divider_en(rtc->reg_a) || period == 0) {
		return;
	}

	/*
	 * Have we crossed the edge of a period-sized time interval since the
	 * last periodic event?
	 */
	hrtime_t since_last = gethrtime() - vrtc->last_period;
	if (since_last > period) {
		vrtc_regc_update(vrtc, RTCIR_PERIOD);
		vrtc->last_period = ROUNDDOWN(since_last, period);
	}
}

/*
 * Update the internal contents of the RTC.  This includes both the date/time
 * information in the CMOS, as well as interrupt flags in register-C.
 */
static void
vrtc_update(struct vrtc *vrtc)
{
	struct rtcdev *rtc = &vrtc->rtcdev;

	ASSERT(VRTC_LOCKED(vrtc));

	/*
	 * If the divider output is disabled, no events will be generated, and
	 * the time will not be updated.
	 */
	if (!rega_divider_en(rtc->reg_a)) {
		return;
	}

	/* Check for any periodic timer events requiring injection. */
	vrtc_periodic_update(vrtc);


	if (vrtc->base_rtctime == VRTC_BROKEN_TIME) {
		/* If RTC updates are disabled, nothing further is required */
		return;
	}

	if (rtc_halted(vrtc)) {
		/*
		 * Neither alarm checks, nor updates to the time stored in CMOS
		 * are performed when the RTC is halted.
		 */
		return;
	}

	/*
	 * Calculate the new time and its corresponding second-granularity clock
	 * edge from the divider for base_clock.
	 */
	hrtime_t basetime;
	const time_t newtime = vrtc_curtime(vrtc, &basetime, NULL);
	if (vrtc->base_rtctime >= newtime) {
		/* Nothing more to do if the actual time is unchanged */
		return;
	}
	vrtc->base_clock = basetime;

	if ((rtc->reg_c & RTCIR_ALARM) != 0) {
		/*
		 * If the alarm event is already pending, there is no need to
		 * match the RTC time against it, since any additional assertion
		 * will be redundant until the flag is read/cleared.
		 */
		vrtc->base_rtctime = newtime;
	} else {
		/*
		 * Check if any of the times (down to the second) between the
		 * old time and the new match against a configured alarm
		 * condition.
		 */
		const uint8_t alarm_sec = rtc->alarm_sec;
		const uint8_t alarm_min = rtc->alarm_min;
		const uint8_t alarm_hour = rtc->alarm_hour;
		do {
			vrtc->base_rtctime++;
			vrtc_time_to_cmos(vrtc, false);

			if ((alarm_sec >= 0xC0 || alarm_sec == rtc->sec) &&
			    (alarm_min >= 0xC0 || alarm_min == rtc->min) &&
			    (alarm_hour >= 0xC0 || alarm_hour == rtc->hour)) {
				vrtc_regc_update(vrtc, RTCIR_ALARM);
				/*
				 * Once the alarm triggers once during this
				 * check, we can skip to the end, since
				 * subsequent firings would be redundant while
				 * the lock is held
				 */
				vrtc->base_rtctime = newtime;
			}
		} while (vrtc->base_rtctime != newtime);
	}

	/* Reflect that the time underwent an update */
	vrtc_regc_update(vrtc, RTCIR_UPDATE);
}

static void
vrtc_callout_handler(void *arg)
{
	struct vrtc *vrtc = arg;

	VRTC_LOCK(vrtc);
	if (callout_pending(&vrtc->callout)) {
		/* callout was reset */
	} else if (!callout_active(&vrtc->callout)) {
		/* callout was stopped */
	} else {
		callout_deactivate(&vrtc->callout);

		/* Perform the actual update, reschedule (if needed) */
		vrtc_update(vrtc);
		vrtc_callout_reschedule(vrtc);
	}
	VRTC_UNLOCK(vrtc);
}

static void
vrtc_callout_reschedule(struct vrtc *vrtc)
{
	struct rtcdev *rtc = &vrtc->rtcdev;

	ASSERT(VRTC_LOCKED(vrtc));

	hrtime_t period = 0;
	if ((rtc->reg_b & RTCSB_PINTR) != 0) {
		/*
		 * Calculate the next event edge using the periodic timer, since
		 * it will be more granular (2Hz or faster) than the 1Hz used by
		 * the alarm and update interrupts, and still in phase.
		 */
		period = rega_period(rtc->reg_a);
	}
	if (period == 0 && rtc_update_enabled(vrtc)) {
		/*
		 * If RTC updates are enabled, there is potential for update or
		 * alarm interrupts on 1Hz intervals.
		 */
		period = NANOSEC;
	}

	/*
	 * RTC callouts are only required if interrupts are enabled, since all
	 * other side effects of time moving forward (such as setting of the
	 * event bits in register-C) can be conjured on-demand when those fields
	 * are read by the guest.  The same is true when an interrupt has been
	 * asserted and not yet handled.
	 */
	const bool intr_enabled = (rtc->reg_b & RTCSB_INTR_MASK) != 0;
	const bool intr_asserted = (rtc->reg_c & RTCIR_INT) != 0;
	if (period != 0 && intr_enabled && !intr_asserted) {
		/*
		 * Find the next edge of the specified period interval,
		 * referenced against the phase of base_clock.
		 */
		const hrtime_t delta = gethrtime() + period - vrtc->base_clock;
		const hrtime_t next =
		    ROUNDDOWN(delta, period) + vrtc->base_clock;

		callout_reset_hrtime(&vrtc->callout, next, vrtc_callout_handler,
		    vrtc, C_ABSOLUTE);
	} else {
		if (callout_active(&vrtc->callout)) {
			callout_stop(&vrtc->callout);
		}
	}
}

/*
 * We can take some shortcuts in the register-B/register-C math since the
 * interrupt-enable bits match their corresponding interrupt-present bits.
 */
CTASSERT(RTCIR_UPDATE == RTCSB_UINTR);
CTASSERT(RTCIR_ALARM == RTCSB_AINTR);
CTASSERT(RTCIR_PERIOD == RTCSB_PINTR);


/*
 * Update the contents of register-C either due to newly asserted events, or
 * altered interrupt-enable flags.
 */
static void
vrtc_regc_update(struct vrtc *vrtc, uint8_t events)
{
	struct rtcdev *rtc = &vrtc->rtcdev;

	ASSERT(VRTC_LOCKED(vrtc));
	ASSERT0(events & ~(RTCSB_INTR_MASK));

	/*
	 * Regardless of which interrupt enable flags are set in register-B, the
	 * corresponding event flags are always set in register-C.
	 */
	rtc->reg_c |= events;

	const bool oldirq = (rtc->reg_c & RTCIR_INT) != 0;
	if ((rtc->reg_b & RTCSB_INTR_MASK & rtc->reg_c) != 0) {
		rtc->reg_c |= RTCIR_INT;
	}
	const bool newirq = (rtc->reg_c & RTCIR_INT) != 0;

	/*
	 * Although this should probably be asserting level-triggered interrupt,
	 * the original logic from bhyve is event-triggered.  This may warrant
	 * additional consideration at some point.
	 */
	if (!oldirq && newirq) {
		/* IRQ asserted */
		(void) vatpic_pulse_irq(vrtc->vm, RTC_IRQ);
		(void) vioapic_pulse_irq(vrtc->vm, RTC_IRQ);
	} else if (oldirq && !newirq) {
		/* IRQ de-asserted */
	}
}

/*
 * Emulate a read of register-C, emitting the contained value and clearing its
 * contents for subsequent actions.
 */
static uint8_t
vrtc_regc_read(struct vrtc *vrtc)
{
	struct rtcdev *rtc = &vrtc->rtcdev;

	ASSERT(VRTC_LOCKED(vrtc));

	const uint8_t val = rtc->reg_c;

	/*
	 * Clear the IRQ flag, and any interrupt flags which have been
	 * correspondingly enabled in register B.
	 */
	const uint8_t active_flags = rtc->reg_b & RTCSB_INTR_MASK;
	rtc->reg_c = (rtc->reg_c & RTCSB_INTR_MASK) & (~active_flags);

	return (val);
}

static void
vrtc_regb_write(struct vrtc *vrtc, uint8_t newval)
{
	struct rtcdev *rtc = &vrtc->rtcdev;

	ASSERT(VRTC_LOCKED(vrtc));

	uint8_t changed = rtc->reg_b ^ newval;
	rtc->reg_b = newval;

	if (changed & RTCSB_HALT) {
		if ((newval & RTCSB_HALT) == 0) {
			/*
			 * RTC is coming out of a halted state.
			 *
			 * Push the base time (the clock from the divider)
			 * forward to the nearest second boundary so it may
			 * resume updates from the value set in the CMOS.
			 */
			vrtc->base_rtctime = vrtc_cmos_to_secs(vrtc);
		} else {
			/*
			 * Force a refresh of the RTC date/time fields so
			 * they reflect the time right before the guest set
			 * the HALT bit.
			 */
			vrtc_update(vrtc);
			vrtc_time_to_cmos(vrtc, true);

			/*
			 * Updates are halted so mark 'base_rtctime' to denote
			 * that the RTC date/time is in flux.
			 *
			 * Since the HALT/RUN flag does not effect the actual
			 * phase of the clock emitted from the emulated divider,
			 * the base time will remain unchanged
			 */
			vrtc->base_rtctime = VRTC_BROKEN_TIME;

			/*
			 * Per the specification, the UINTR bit must be cleared
			 * if the HALT bit is set.
			 */
			if ((rtc->reg_b & RTCSB_UINTR) != 0) {
				rtc->reg_b &= ~RTCSB_UINTR;
				changed |= RTCSB_UINTR;
			}
		}
	}

	/* Side effect of changes to the interrupt enable bits.  */
	if (changed & RTCSB_INTR_MASK) {
		vrtc_regc_update(vrtc, 0);
	}

	vrtc_callout_reschedule(vrtc);

	/*
	 * The side effect of bits that control the RTC date/time format
	 * is handled lazily when those fields are actually read.
	 */
}

static void
vrtc_rega_write(struct vrtc *vrtc, uint8_t newval)
{
	ASSERT(VRTC_LOCKED(vrtc));

	const uint8_t oldval = vrtc->rtcdev.reg_a;
	if (rega_divider_en(oldval) && !rega_divider_en(newval)) {
		/* RTC divider held in reset */
	} else if (!rega_divider_en(oldval) && rega_divider_en(newval)) {
		/*
		 * Divider is coming out of reset.  Updates of the reported time
		 * (if enabled) are expected to begin 500ms from now.
		 */
		vrtc->base_rtctime = vrtc_cmos_to_secs(vrtc);
		vrtc->base_clock = gethrtime() - (NANOSEC / 2);
		vrtc->last_period = vrtc->base_clock;
	}

	/*
	 * We never present the time-update bit as a device, nor is the consumer
	 * allowed to set it during a write.
	 */
	vrtc->rtcdev.reg_a = newval & ~RTCSA_TUP;

	vrtc_callout_reschedule(vrtc);
}

int
vrtc_set_time(struct vm *vm, const timespec_t *ts)
{
	struct vrtc *vrtc = vm_rtc(vm);

	if (ts->tv_sec < 0 || ts->tv_nsec >= NANOSEC) {
		/*
		 * Times before the 1970 epoch, or with nonsensical nanosecond
		 * counts are not supported
		 */
		return (EINVAL);
	}

	VRTC_LOCK(vrtc);
	vrtc->base_rtctime = ts->tv_sec;
	vrtc->base_clock = gethrtime() - ts->tv_nsec;
	vrtc->last_period = vrtc->base_clock;
	if (!vm_is_paused(vrtc->vm)) {
		vrtc_callout_reschedule(vrtc);
	}
	VRTC_UNLOCK(vrtc);

	return (0);
}

void
vrtc_get_time(struct vm *vm, timespec_t *ts)
{
	struct vrtc *vrtc = vm_rtc(vm);
	hrtime_t phase;

	VRTC_LOCK(vrtc);
	ts->tv_sec = vrtc_curtime(vrtc, NULL, &phase);
	ts->tv_nsec = phase;
	VRTC_UNLOCK(vrtc);
}

int
vrtc_nvram_write(struct vm *vm, int offset, uint8_t value)
{
	struct vrtc *vrtc;
	uint8_t *ptr;

	vrtc = vm_rtc(vm);

	/*
	 * Don't allow writes to RTC control registers or the date/time fields.
	 */
	if (offset < offsetof(struct rtcdev, nvram[0]) ||
	    offset == RTC_CENTURY || offset >= sizeof (struct rtcdev)) {
		/* NVRAM write to invalid offset */
		return (EINVAL);
	}

	VRTC_LOCK(vrtc);
	ptr = (uint8_t *)(&vrtc->rtcdev);
	ptr[offset] = value;
	VRTC_UNLOCK(vrtc);

	return (0);
}

int
vrtc_nvram_read(struct vm *vm, int offset, uint8_t *retval)
{
	struct vrtc *vrtc;
	uint8_t *ptr;

	/* Allow all offsets in the RTC to be read.  */
	if (offset < 0 || offset >= sizeof (struct rtcdev)) {
		return (EINVAL);
	}

	vrtc = vm_rtc(vm);
	VRTC_LOCK(vrtc);

	/* Update RTC date/time fields if necessary.  */
	if (offset < 10 || offset == RTC_CENTURY) {
		vrtc_update(vrtc);
		vrtc_time_to_cmos(vrtc, false);
	}

	ptr = (uint8_t *)(&vrtc->rtcdev);
	*retval = ptr[offset];

	VRTC_UNLOCK(vrtc);
	return (0);
}

int
vrtc_addr_handler(void *arg, bool in, uint16_t port, uint8_t bytes,
    uint32_t *val)
{
	struct vrtc *vrtc = arg;

	if (bytes != 1)
		return (-1);

	if (in) {
		*val = 0xff;
		return (0);
	}

	VRTC_LOCK(vrtc);
	vrtc->addr = *val & 0x7f;
	VRTC_UNLOCK(vrtc);

	return (0);
}

int
vrtc_data_handler(void *arg, bool in, uint16_t port, uint8_t bytes,
    uint32_t *val)
{
	struct vrtc *vrtc = arg;
	uint8_t *rtc_raw = (uint8_t *)&vrtc->rtcdev;

	if (bytes != 1) {
		return (-1);
	}

	VRTC_LOCK(vrtc);
	const uint8_t offset = vrtc->addr;
	if (offset >= sizeof (struct rtcdev)) {
		VRTC_UNLOCK(vrtc);
		return (-1);
	}

	vrtc_update(vrtc);

	/*
	 * Update RTC date/time fields if necessary.
	 *
	 * This is not just for reads of the RTC. The side-effect of writing
	 * the century byte requires other RTC date/time fields (e.g. sec)
	 * to be updated here.
	 */
	if (offset < 10 || offset == RTC_CENTURY) {
		vrtc_time_to_cmos(vrtc, false);
	}

	if (in) {
		switch (offset) {
		case RTC_INTR:
			/* A read of register C clears the flags it holds */
			*val = vrtc_regc_read(vrtc);
			break;
		default:
			*val = rtc_raw[offset];
			break;
		}
	} else {
		switch (offset) {
		case RTC_STATUSA:
			vrtc_rega_write(vrtc, *val);
			break;
		case RTC_STATUSB:
			vrtc_regb_write(vrtc, *val);
			break;
		case RTC_INTR:
			/* Ignored write to reg_c */
			break;
		case RTC_STATUSD:
			/* Ignored write to reg_d */
			break;
		case RTC_SEC:
			/* High order bit of 'seconds' is read-only.  */
			*val &= 0x7f;
			/* FALLTHRU */
		default:
			rtc_raw[offset] = *val;
			break;
		}

		/*
		 * Some guests (e.g. OpenBSD) write the century byte
		 * outside of RTCSB_HALT so unconditionally recalculate the
		 * date/time if that byte is written.
		 */
		if (offset == RTC_CENTURY && !rtc_halted(vrtc)) {
			vrtc->base_rtctime = vrtc_cmos_to_secs(vrtc);
		}
	}
	VRTC_UNLOCK(vrtc);
	return (0);
}

void
vrtc_reset(struct vrtc *vrtc)
{
	struct rtcdev *rtc = &vrtc->rtcdev;

	VRTC_LOCK(vrtc);

	vrtc_regb_write(vrtc, rtc->reg_b & ~(RTCSB_INTR_MASK | RTCSB_SQWE));
	rtc->reg_c = 0;
	ASSERT(!callout_active(&vrtc->callout));

	VRTC_UNLOCK(vrtc);
}

struct vrtc *
vrtc_init(struct vm *vm)
{
	struct vrtc *vrtc;
	struct rtcdev *rtc;

	vrtc = kmem_zalloc(sizeof (struct vrtc), KM_SLEEP);
	vrtc->vm = vm;
	mutex_init(&vrtc->lock, NULL, MUTEX_ADAPTIVE, NULL);
	callout_init(&vrtc->callout, 1);

	/* Allow dividers to keep time but disable everything else */
	rtc = &vrtc->rtcdev;
	rtc->reg_a = RTCSA_DIVIDER_32K;
	rtc->reg_b = RTCSB_24HR;
	rtc->reg_c = 0;
	rtc->reg_d = RTCSD_PWR;

	/* Reset the index register to a safe value. */
	vrtc->addr = RTC_STATUSD;

	VRTC_LOCK(vrtc);
	/* Initialize RTC time to 00:00:00 1 January, 1970.  */
	vrtc->base_rtctime = 0;
	vrtc->base_clock = gethrtime();
	vrtc->last_period = vrtc->base_clock;
	vrtc_time_to_cmos(vrtc, false);
	VRTC_UNLOCK(vrtc);

	return (vrtc);
}

void
vrtc_cleanup(struct vrtc *vrtc)
{
	callout_drain(&vrtc->callout);
	mutex_destroy(&vrtc->lock);
	kmem_free(vrtc, sizeof (*vrtc));
}

void
vrtc_localize_resources(struct vrtc *vrtc)
{
	vmm_glue_callout_localize(&vrtc->callout);
}

void
vrtc_pause(struct vrtc *vrtc)
{
	VRTC_LOCK(vrtc);
	callout_stop(&vrtc->callout);
	VRTC_UNLOCK(vrtc);
}

void
vrtc_resume(struct vrtc *vrtc)
{
	VRTC_LOCK(vrtc);
	ASSERT(!callout_active(&vrtc->callout));
	vrtc_callout_reschedule(vrtc);
	VRTC_UNLOCK(vrtc);
}

static int
vrtc_data_read(void *datap, const vmm_data_req_t *req)
{
	VERIFY3U(req->vdr_class, ==, VDC_RTC);
	VERIFY3U(req->vdr_version, ==, 2);
	VERIFY3U(req->vdr_len, >=, sizeof (struct vdi_rtc_v2));

	struct vrtc *vrtc = datap;
	struct vdi_rtc_v2 *out = req->vdr_data;

	VRTC_LOCK(vrtc);

	out->vr_addr = vrtc->addr;
	out->vr_base_clock = vm_normalize_hrtime(vrtc->vm, vrtc->base_clock);
	out->vr_last_period = vm_normalize_hrtime(vrtc->vm, vrtc->last_period);
	bcopy(&vrtc->rtcdev, out->vr_content, sizeof (out->vr_content));

	VRTC_UNLOCK(vrtc);

	return (0);
}

static int
vrtc_data_write(void *datap, const vmm_data_req_t *req)
{
	VERIFY3U(req->vdr_class, ==, VDC_RTC);
	VERIFY3U(req->vdr_version, ==, 2);
	VERIFY3U(req->vdr_len, >=, sizeof (struct vdi_rtc_v2));

	struct vrtc *vrtc = datap;
	const struct vdi_rtc_v2 *src = req->vdr_data;

	const hrtime_t base_clock =
	    vm_denormalize_hrtime(vrtc->vm, src->vr_base_clock);
	const hrtime_t last_period =
	    vm_denormalize_hrtime(vrtc->vm, src->vr_last_period);

	const hrtime_t now = gethrtime();
	if (base_clock > now || last_period > now) {
		/*
		 * Neither the base clock nor the last periodic event edge
		 * should be in the future, since they should trail (or at most
		 * equal) the current time.
		 */
		return (EINVAL);
	}

	/*
	 * The phase of last_period could be checked against that of base_clock,
	 * but for now, any shenanigans there will go unhandled.
	 */

	VRTC_LOCK(vrtc);

	vrtc->base_clock = base_clock;
	bcopy(src->vr_content, &vrtc->rtcdev, sizeof (vrtc->rtcdev));
	vrtc->addr = src->vr_addr;

	vrtc->rtcdev.reg_a &= ~RTCSA_TUP;
	/* register B needs requires no masking */
	vrtc->rtcdev.reg_c &= RTCSC_MASK;
	vrtc->rtcdev.reg_d = RTCSD_PWR;

	/* Set internal time based on what is stored in CMOS */
	vrtc->base_rtctime = vrtc_cmos_to_secs(vrtc);
	/* Using the specified divider edge timing */
	vrtc->base_clock = base_clock;
	vrtc->last_period = last_period;

	if (!vm_is_paused(vrtc->vm)) {
		vrtc_callout_reschedule(vrtc);
	}

	VRTC_UNLOCK(vrtc);
	return (0);
}

static const vmm_data_version_entry_t rtc_v2 = {
	.vdve_class = VDC_RTC,
	.vdve_version = 2,
	.vdve_len_expect = sizeof (struct vdi_rtc_v2),
	.vdve_readf = vrtc_data_read,
	.vdve_writef = vrtc_data_write,
};
VMM_DATA_VERSION(rtc_v2);
