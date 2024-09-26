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

#include <sys/kernel.h>
#include <sys/x86_archext.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>

#include <sys/vmm_kernel.h>
#include "svm.h"
#include "svm_softc.h"
#include "svm_pmu.h"

int svm_pmu_enabled = 0;
int svm_pmu_force_exit = 0;


struct host_cpc_state {
	uint64_t hcs_evsel[SVM_PMU_MAX_COUNTERS];
	uint64_t hcs_cnt[SVM_PMU_MAX_COUNTERS];
};

static struct host_cpc_state svm_host_state[NCPU];

void
svm_pmu_init(struct svm_softc *svm_sc)
{
	const bool is_enabled =
	    is_x86_feature(x86_featureset, X86FSET_AMD_PCEC) &&
	    svm_pmu_enabled != 0;

	svm_sc->pmu.sp_enabled = is_enabled;

	if (chiprev_family(cpuid_getchiprev(CPU)) < 0x17) {
		svm_sc->pmu.sp_flavor = SPF_PRE_ZEN;
	} else {
		/*
		 * Filtering of accessible perf counters only cares about Zen vs
		 * pre-Zen presently, so bucket all Zen chips as v1
		 */
		svm_sc->pmu.sp_flavor = SPF_ZEN1;
	}
}

bool
svm_pmu_owned_msr(uint32_t msr)
{
	switch (msr) {
	case MSR_AMD_K7_PERF_EVSEL0:
	case MSR_AMD_K7_PERF_EVSEL1:
	case MSR_AMD_K7_PERF_EVSEL2:
	case MSR_AMD_K7_PERF_EVSEL3:

	case MSR_AMD_K7_PERF_CTR0:
	case MSR_AMD_K7_PERF_CTR1:
	case MSR_AMD_K7_PERF_CTR2:
	case MSR_AMD_K7_PERF_CTR3:

	case MSR_AMD_F15H_PERF_EVSEL0:
	case MSR_AMD_F15H_PERF_EVSEL1:
	case MSR_AMD_F15H_PERF_EVSEL2:
	case MSR_AMD_F15H_PERF_EVSEL3:
	case MSR_AMD_F15H_PERF_EVSEL4:
	case MSR_AMD_F15H_PERF_EVSEL5:

	case MSR_AMD_F15H_PERF_CTR0:
	case MSR_AMD_F15H_PERF_CTR1:
	case MSR_AMD_F15H_PERF_CTR2:
	case MSR_AMD_F15H_PERF_CTR3:
	case MSR_AMD_F15H_PERF_CTR4:
	case MSR_AMD_F15H_PERF_CTR5:
		return (true);
	default:
		return (false);
	}
}

/*
 * Map the "legacy" MSRs identifiers onto their aliases in the extended space.
 */
static uint32_t
svm_pmu_legacy_to_extd(uint32_t msr)
{
	if (msr >= MSR_AMD_K7_PERF_CTR0 &&
	    msr <= MSR_AMD_K7_PERF_CTR3) {
		return (MSR_AMD_F15H_PERF_CTR0 +
		    (msr - MSR_AMD_K7_PERF_CTR0) * 2);
	} else if (msr >= MSR_AMD_K7_PERF_EVSEL0 &&
	    msr <= MSR_AMD_K7_PERF_EVSEL3) {
		return (MSR_AMD_F15H_PERF_EVSEL0 +
		    (msr - MSR_AMD_K7_PERF_EVSEL0) * 2);
	} else {
		return (msr);
	}
}

static bool
svm_pmu_evsel_allowed(uint64_t evsel, svm_pmu_flavor_t flavor)
{
	const uint64_t evt = evsel & AMD_PERF_EVSEL_EVT_MASK;

	/*
	 * Some of the perf counters have stayed fairly consistent in their
	 * identifiers throughout the AMD product line.
	 */
	switch (evt) {
	case 0x76:	/* CPU cycles */
	case 0xc0:	/* Retired instructions */
	case 0xc2:	/* Branch instructions */
	case 0xc3:	/* Branch misses */
		return (true);
	default:
		break;
	}

	switch (flavor) {
	case SPF_PRE_ZEN:
		switch (evt) {
		case 0x7d: /* Cache hits */
		case 0x7e: /* Cache misses */
			return (true);
		default:
			return (false);
		}
		break;
	case SPF_ZEN1:
		switch (evt) {
		case 0x60: /* L2 cache references (umask:ff for hits) */
		case 0x64: /* L2 cache references (umask:09 for misses) */
			return (true);
		default:
			return (false);
		}
		break;
	default:
		return (false);
	}
}

vm_msr_result_t
svm_pmu_rdmsr(struct svm_softc *svm_sc, int vcpu, uint32_t msr, uint64_t *valp)
{
	ASSERT(svm_pmu_owned_msr(msr));

	struct svm_pmu_vcpu *pmu = svm_get_pmu(svm_sc, vcpu);

	if (!svm_sc->pmu.sp_enabled) {
		return (VMR_UNHANLDED);
	}

	msr = svm_pmu_legacy_to_extd(msr);
	uint_t idx = 0;
	switch (msr) {
	case MSR_AMD_F15H_PERF_EVSEL0:
	case MSR_AMD_F15H_PERF_EVSEL1:
	case MSR_AMD_F15H_PERF_EVSEL2:
	case MSR_AMD_F15H_PERF_EVSEL3:
	case MSR_AMD_F15H_PERF_EVSEL4:
	case MSR_AMD_F15H_PERF_EVSEL5:
		idx = (msr - MSR_AMD_F15H_PERF_EVSEL0) / 2;
		*valp = pmu->spv_msr_evsel_shadow[idx];
		break;
	case MSR_AMD_F15H_PERF_CTR0:
	case MSR_AMD_F15H_PERF_CTR1:
	case MSR_AMD_F15H_PERF_CTR2:
	case MSR_AMD_F15H_PERF_CTR3:
	case MSR_AMD_F15H_PERF_CTR4:
	case MSR_AMD_F15H_PERF_CTR5:
		idx = (msr - MSR_AMD_F15H_PERF_CTR0) / 2;
		*valp = pmu->spv_msr_cnt[idx];
		break;
	default:
		panic("unexpected perf counter msr %x", msr);
		break;
	}

	return (VMR_OK);
}

/*
 * For now, we allow practically all of the perf control bits through (once the
 * event selector is confirmed to be one we allow), save for the host/guest
 * bits, which we obviously use to isolate the host and guest metrics.
 */
#define	AMD_PERF_CTRL_ALLOW_MASK	\
				(AMD_PERF_EVSEL_EVT_MASK | \
				AMD_PERF_EVSEL_UNIT_MASK | \
				AMD_PERF_EVSEL_USER_MODE | \
				AMD_PERF_EVSEL_OS_MODE | \
				AMD_PERF_EVSEL_EDGE | \
				AMD_PERF_EVSEL_INT_EN | \
				AMD_PERF_EVSEL_CTR_EN | \
				AMD_PERF_EVSEL_INV_CMP | \
				AMD_PERF_EVSEL_CNT_MASK)

static void
svm_pmu_update(struct svm_softc *svm_sc, int vcpuid)
{
	struct svm_pmu_vcpu *pmu = svm_get_pmu(svm_sc, vcpuid);
	const svm_pmu_flavor_t flavor = svm_sc->pmu.sp_flavor;

	svm_pmu_state_flags_t new_flags = SPSF_DISABLED;
	for (uint_t i = 0; i < SVM_PMU_MAX_COUNTERS; i++) {
		/*
		 * XXX: until interrupt stuff is figured out, just mask the bit
		const uint64_t shadow_evsel = pmu->spv_msr_evsel_shadow[i];
		 */
		const uint64_t shadow_evsel =
		    pmu->spv_msr_evsel_shadow[i] & ~AMD_PERF_EVSEL_INT_EN;

		if (!svm_pmu_evsel_allowed(shadow_evsel, flavor)) {
			/*
			 * Zero out the perf counter control (which clears the
			 * counter-enable and interrupt-enable bits) if the
			 * guest specified an event selector which we do not
			 * allow access to.
			 */
			pmu->spv_msr_evsel[i] = 0;
			continue;
		}

		if ((shadow_evsel & AMD_PERF_EVSEL_CTR_EN) != 0) {
			new_flags |= SPSF_CTR_EN;
		}
		if ((shadow_evsel & AMD_PERF_EVSEL_INT_EN) != 0) {
			new_flags |= SPSF_INTR_EN;
		}

		pmu->spv_msr_evsel[i] =
		    (shadow_evsel & AMD_PERF_CTRL_ALLOW_MASK) |
		    AMD_PERF_EVSEL_HG_GUEST;
	}

	const svm_pmu_state_flags_t old_flags = pmu->spv_state;
	pmu->spv_state = new_flags;

	if (svm_pmu_force_exit != 0) {
		/*
		 * XXX: don't need to twiddle with intercepts if we expect exits
		 * for all perfctr access.
		 */
		return;
	}

	/*
	 * When counters are configured an enabled, allow direct access to the
	 * MSRs for the counter values.  Nothing in these needs to be shadowed
	 * from the guest, so skipping the need for VM exits when the guest
	 * samples them is beneficial.
	 */
	const uint32_t direct_msrs[] = {
		MSR_AMD_K7_PERF_CTR0, MSR_AMD_K7_PERF_CTR1,
		MSR_AMD_K7_PERF_CTR2, MSR_AMD_K7_PERF_CTR3,

		MSR_AMD_F15H_PERF_CTR0, MSR_AMD_F15H_PERF_CTR1,
		MSR_AMD_F15H_PERF_CTR2, MSR_AMD_F15H_PERF_CTR3,
		MSR_AMD_F15H_PERF_CTR4, MSR_AMD_F15H_PERF_CTR5,
	};

	if ((old_flags & SPSF_CTR_EN) == 0 &&
	    (new_flags & SPSF_CTR_EN) != 0) {
		/*
		 * With counters now enabled in the guest, drop the intercept to
		 * RDPMC, and allow direct R/W access to the counter MSRs.
		 */
		svm_disable_intercept(svm_sc, vcpuid, VMCB_CTRL1_INTCPT,
		    VMCB_INTCPT_RDPMC);
		for (uint_t i = 0; i < ARRAY_SIZE(direct_msrs); i++) {
			svm_msr_set_access(svm_sc, vcpuid, direct_msrs[i],
			    SMP_READ | SMP_WRITE);
		}
	} else if ((old_flags & SPSF_CTR_EN) != 0 &&
	    (new_flags & SPSF_CTR_EN) == 0) {
		/*
		 * With counters now disabled in the guest, re-enable the
		 * intercept to RDPMC, and disallow direct R/W access to the
		 * counter MSRs.
		 */
		svm_enable_intercept(svm_sc, vcpuid, VMCB_CTRL1_INTCPT,
		    VMCB_INTCPT_RDPMC);

		for (uint_t i = 0; i < ARRAY_SIZE(direct_msrs); i++) {
			svm_msr_set_access(svm_sc, vcpuid, direct_msrs[i],
			    SMP_NONE);
		}
	}
}

vm_msr_result_t
svm_pmu_wrmsr(struct svm_softc *svm_sc, int vcpu, uint32_t msr, uint64_t val)
{
	ASSERT(svm_pmu_owned_msr(msr));

	struct svm_pmu_vcpu *pmu = svm_get_pmu(svm_sc, vcpu);

	if (!svm_sc->pmu.sp_enabled) {
		return (VMR_UNHANLDED);
	}

	msr = svm_pmu_legacy_to_extd(msr);
	uint_t idx = 0;
	switch (msr) {
	case MSR_AMD_F15H_PERF_EVSEL0:
	case MSR_AMD_F15H_PERF_EVSEL1:
	case MSR_AMD_F15H_PERF_EVSEL2:
	case MSR_AMD_F15H_PERF_EVSEL3:
	case MSR_AMD_F15H_PERF_EVSEL4:
	case MSR_AMD_F15H_PERF_EVSEL5:
		idx = (msr - MSR_AMD_F15H_PERF_EVSEL0) / 2;
		/* XXX: balk at reserved bits being set? */
		pmu->spv_msr_evsel_shadow[idx] = val;
		svm_pmu_update(svm_sc, vcpu);
		break;
	case MSR_AMD_F15H_PERF_CTR0:
	case MSR_AMD_F15H_PERF_CTR1:
	case MSR_AMD_F15H_PERF_CTR2:
	case MSR_AMD_F15H_PERF_CTR3:
	case MSR_AMD_F15H_PERF_CTR4:
	case MSR_AMD_F15H_PERF_CTR5:
		idx = (msr - MSR_AMD_F15H_PERF_CTR0) / 2;
		pmu->spv_msr_cnt[idx] = val;
		break;
	default:
		panic("unexpected perf counter msr %x", msr);
		break;
	}

	return (VMR_OK);
}

bool
svm_pmu_rdpmc(struct svm_softc *svm_sc, int vcpu, uint32_t ecx, uint64_t *valp)
{
	if (!svm_sc->pmu.sp_enabled) {
		return (false);
	}
	if (ecx >= SVM_PMU_MAX_COUNTERS) {
		return (false);
	}

	struct svm_pmu_vcpu *pmu = svm_get_pmu(svm_sc, vcpu);
	*valp = pmu->spv_msr_cnt[ecx];
	return (true);
}

bool
svm_pmu_enter(struct svm_softc *svm_sc, int vcpu)
{
	struct svm_pmu_vcpu *pmu = svm_get_pmu(svm_sc, vcpu);

	if ((pmu->spv_state & SPSF_CTR_EN) == 0) {
		return (false);
	}

	struct host_cpc_state *host = &svm_host_state[CPU->cpu_seqid];

	/* Save existing host state */
	bool intr_enabled = false;
	for (uint_t i = 0; i < SVM_PMU_MAX_COUNTERS; i++) {
		host->hcs_evsel[i] = rdmsr(MSR_AMD_F15H_PERF_EVSEL0 + (i * 2));
		host->hcs_cnt[i] = rdmsr(MSR_AMD_F15H_PERF_CTR0 + (i * 2));
		if ((host->hcs_evsel[i] & AMD_PERF_EVSEL_INT_EN) != 0) {
			intr_enabled = true;
		}
	}
	if (intr_enabled) {
		/*
		 * XXX: check for pending CPC interrupt, since it would be held
		 * by gintr masking.  If present, return true, and take lap.
		 */
	}

	/* Load the guest state */
	for (uint_t i = 0; i < SVM_PMU_MAX_COUNTERS; i++) {
		wrmsr(MSR_AMD_F15H_PERF_EVSEL0 + (i * 2),
		    pmu->spv_msr_evsel[i]);
		wrmsr(MSR_AMD_F15H_PERF_CTR0 + (i * 2), pmu->spv_msr_cnt[i]);
	}

	/* XXX: no bail-out conditions for now */
	return (false);
}

void
svm_pmu_exit(struct svm_softc *svm_sc, int vcpu)
{
	struct svm_pmu_vcpu *pmu = svm_get_pmu(svm_sc, vcpu);

	if ((pmu->spv_state & SPSF_CTR_EN) == 0) {
		return;
	}

	if ((pmu->spv_state & SPSF_INTR_EN) != 0) {
		/*
		 * XXX: check for pending CPC interrupt.  If present, it belongs
		 * to the guest and needs to be plucked from the normal handling
		 * logic and instead queued on the virtual APIC.
		 *
		 * if (check_for_pending_cpc_intr()) {
		 * 	enable_gintr();
		 * 	// interrupt should be delivered here
		 * 	disable_gintr();
		 * }
		 * After this point, we can load the host counters again, since
		 * we will not have to disambiguate between an interrupt
		 * triggerd from the guest or host.
		 */
	}

	/* Save guest counter contents.
	 *
	 * Direct guest access to the control registers is not allowed, so those
	 * do not need to saved here.
	 */
	for (uint_t i = 0; i < SVM_PMU_MAX_COUNTERS; i++) {
		pmu->spv_msr_cnt[i] = rdmsr(MSR_AMD_F15H_PERF_CTR0 + (i * 2));
	}

	/*
	 * Load the host state back in.  Enabling of the counters is done last,
	 * in the hopes that any of those which are thusly configured will start
	 * counting at as close to the same time as possible.
	 */
	struct host_cpc_state *host = &svm_host_state[CPU->cpu_seqid];
	for (uint_t i = 0; i < SVM_PMU_MAX_COUNTERS; i++) {
		wrmsr(MSR_AMD_F15H_PERF_EVSEL0 + (i * 2),
		    host->hcs_evsel[i] & ~AMD_PERF_EVSEL_CTR_EN);
		wrmsr(MSR_AMD_F15H_PERF_CTR0 + (i * 2),
		    host->hcs_cnt[i]);
	}
	for (uint_t i = 0; i < SVM_PMU_MAX_COUNTERS; i++) {
		wrmsr(MSR_AMD_F15H_PERF_EVSEL0 + (i * 2), host->hcs_evsel[i]);
	}
}
