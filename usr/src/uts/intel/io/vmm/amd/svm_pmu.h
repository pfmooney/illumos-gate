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
 * Copyright 2024 Oxide Computer Company
 */

#ifndef _SVM_PMU_H
#define	_SVM_PMU_H

#include <sys/stdbool.h>
#include <sys/vmm_kernel.h>

#include "svm_softc.h"

#define	SVM_PMU_MAX_COUNTERS	6

typedef enum svm_pmu_state_flags {
	SPSF_DISABLED = 0,
	SPSF_CTR_EN = (1 << 0),
	SPSF_INTR_EN = (1 << 1),
} svm_pmu_state_flags_t;

struct svm_pmu_vcpu {
	uint64_t spv_msr_evsel[SVM_PMU_MAX_COUNTERS];
	uint64_t spv_msr_evsel_shadow[SVM_PMU_MAX_COUNTERS];
	uint64_t spv_msr_cnt[SVM_PMU_MAX_COUNTERS];
	svm_pmu_state_flags_t spv_state;
};

typedef enum svm_pmu_flavor {
	SPF_PRE_ZEN,
	SPF_ZEN1,
} svm_pmu_flavor_t;

struct svm_pmu {
	bool sp_enabled;
	svm_pmu_flavor_t sp_flavor;
};

void svm_pmu_init(struct svm_softc *);
bool svm_pmu_owned_msr(uint32_t);
vm_msr_result_t svm_pmu_rdmsr(struct svm_softc *, int, uint32_t, uint64_t *);
vm_msr_result_t svm_pmu_wrmsr(struct svm_softc *, int, uint32_t, uint64_t);
bool svm_pmu_rdpmc(struct svm_softc *, int, uint32_t, uint64_t *);
bool svm_pmu_enter(struct svm_softc *, int);
void svm_pmu_exit(struct svm_softc *, int);

#endif /* _SVM_PMU_H */
