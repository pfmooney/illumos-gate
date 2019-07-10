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
 * Copyright 2019 Joyent, Inc.
 */


#include "thr_uberdata.h"
#include <cp_defs.h>

extern hrtime_t __gethrtime_sys();

hrtime_t
gethrtime(void)
{
	comm_page_t *cp = (comm_page_t *)__uberdata.ub_comm_page;

	if (cp != NULL && __cp_can_gettime(cp) != 0) {
		return (__cp_gethrtime(cp));
	}
	return (__gethrtime_sys());
}
