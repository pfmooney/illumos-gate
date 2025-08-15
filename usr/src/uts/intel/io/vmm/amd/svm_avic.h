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
 * Copyright 2025 Oxide Computer Company
 */

#ifndef _SVM_AVIC_H
#define	_SVM_AVIC_H

#include <sys/stdbool.h>
#include <sys/vmm_kernel.h>

#include "svm_softc.h"

void svm_avic_probe(void);

#endif /* _SVM_AVIC_H */
