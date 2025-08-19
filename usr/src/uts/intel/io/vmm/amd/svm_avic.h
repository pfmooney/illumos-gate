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

typedef enum svm_avic_flags {
	SAF_AVIC_ACTIVE		= (1 << 0),
} svm_avic_flags_t;

struct svm_vlapic_state {
	struct svm_softc	*svs_softc;
	svm_avic_flags_t	svs_avic_flags;
};

void svm_avic_probe(void);
vcpu_notify_t svm_avic_set_intr_ready(struct vlapic *, uint8_t, bool);
bool svm_avic_notify_doorbell(struct vlapic *);

void svm_vlapic_set_tpr(struct vlapic *, uint8_t);
void svm_vlapic_init(void *, int, struct vlapic *);

#endif /* _SVM_AVIC_H */
