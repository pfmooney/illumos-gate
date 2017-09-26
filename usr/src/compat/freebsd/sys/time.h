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

/*
 * Copyright 2013 Pluribus Networks Inc.
 */

#ifndef _COMPAT_FREEBSD_SYS_TIME_H_
#define	_COMPAT_FREEBSD_SYS_TIME_H_

#include_next <sys/time.h>

#define	tc_precexp	0

struct bintime {
	ulong_t		sec;		/* seconds */
	uint64_t	frac;		/* 64 bit fraction of a second */
};

#define	BT2FREQ(bt)							\
	(((uint64_t)0x8000000000000000 + ((bt)->frac >> 2)) /		\
	    ((bt)->frac >> 1))

#define	FREQ2BT(freq, bt)						\
{									\
	(bt)->sec = 0;							\
	(bt)->frac = ((uint64_t)0x8000000000000000  / (freq)) << 1;	\
}

static __inline void
binuptime(struct bintime *bt)
{
	hrtime_t	now = gethrtime();

	bt->sec = now / 1000000000;
	/* 18446744073 = int(2^64 / 1000000000) = 1ns in 64-bit fractions */
	bt->frac = (now % 1000000000) * (uint64_t)18446744073LL;
}

#define	bintime_cmp(a, b, cmp)						\
	(((a)->sec == (b)->sec) ?					\
	    ((a)->frac cmp (b)->frac) :					\
	    ((a)->sec cmp (b)->sec))

#define	SBT_1US	(1000)

static __inline void
bintime_add(struct bintime *bt, const struct bintime *bt2)
{
	uint64_t u;

	u = bt->frac;
	bt->frac += bt2->frac;
	if (u > bt->frac)
		bt->sec++;
	bt->sec += bt2->sec;
}

static __inline void
bintime_sub(struct bintime *bt, const struct bintime *bt2)
{
	uint64_t u;

	u = bt->frac;
	bt->frac -= bt2->frac;
	if (u < bt->frac)
		bt->sec--;
	bt->sec -= bt2->sec;
}

static __inline void
bintime_mul(struct bintime *bt, u_int x)
{
	uint64_t p1, p2;

	p1 = (bt->frac & 0xffffffffull) * x;
	p2 = (bt->frac >> 32) * x + (p1 >> 32);
	bt->sec *= x;
	bt->sec += (p2 >> 32);
	bt->frac = (p2 << 32) | (p1 & 0xffffffffull);
}

static __inline sbintime_t
bttosbt(const struct bintime bt)
{
	return ((bt.sec * 1000000000) +
	    (((uint64_t)1000000000 * (uint32_t)(bt.frac >> 32)) >> 32));
}

static __inline sbintime_t
sbinuptime(void)
{
	return (gethrtime());
}

#endif	/* _COMPAT_FREEBSD_SYS_TIME_H_ */
