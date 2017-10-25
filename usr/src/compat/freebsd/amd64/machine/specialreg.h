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
 * Copyright 2017 Joyent, Inc.
 */
#ifndef _COMPAT_FREEBSD_AMD64_MACHINE_SPECIALREG_H_
#define	_COMPAT_FREEBSD_AMD64_MACHINE_SPECIALREG_H_

#ifdef _SYS_X86_ARCHEXT_H
/* Our x85_archext conflicts with BSD header for the XFEATURE_ defines */
#undef	XFEATURE_AVX
#undef	XFEATURE_MPX
#undef	XFEATURE_AVX512
#endif

#include <x86/specialreg.h>
#endif /* _COMPAT_FREEBSD_AMD64_MACHINE_SPECIALREG_H_ */
