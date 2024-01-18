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
 * Copyright 2014 Pluribus Networks Inc.
 * Copyright 2018 Joyent, Inc.
 */

#ifndef _COMPAT_FREEBSD_SYS_TYPES_H_
#define	_COMPAT_FREEBSD_SYS_TYPES_H_

#include <sys/_types.h>

typedef __uint8_t	u_int8_t;	/* unsigned integrals (deprecated) */
typedef __uint16_t	u_int16_t;
typedef __uint32_t	u_int32_t;
typedef __uint64_t	u_int64_t;

#ifndef	__VM_OOFFSET_T_DEFINED
#define	__VM_OOFFSET_T_DEFINED
typedef __int64_t vm_ooffset_t;
#endif

#ifndef	__VM_PADDR_T_DEFINED
#define	__VM_PADDR_T_DEFINED
typedef __uint64_t vm_paddr_t;
#endif

#if defined(_KERNEL)
typedef struct __dev_info **device_t;
#endif

#include_next <sys/types.h>

#endif	/* _COMPAT_FREEBSD_SYS_TYPES_H_ */
