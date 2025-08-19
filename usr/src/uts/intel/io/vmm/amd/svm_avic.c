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

#include <sys/kernel.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>
#include <sys/systm.h>
#include <sys/x86_archext.h>

#include <sys/vmm_kernel.h>
#include "svm.h"
#include "svm_softc.h"
#include "svm_avic.h"
#include "vlapic.h"
#include "vlapic_priv.h"


static inline struct svm_vlapic_state *
vlapic_to_svs(struct vlapic *vlapic)
{
	return ((struct svm_vlapic_state *)vlapic->priv);
}

typedef enum svm_avic_capabs {
	SAC_NONE	= 0,		/* No support */
	SAC_AVIC	= (1 << 0),	/* Base AVIC functionality */
	SAC_X2AVIC	= (1 << 1),	/* x2AVIC support */
	SAC_LVT_ACCESS	= (1 << 2),	/* LVT access decoding */

	/* Known influences to capabilities due to errata: */
	SAC_ERRATA_IPI	= (1 << 16),	/* erratum 1235: broken IPI virt. */
} svm_avic_capabs_t;

static svm_avic_capabs_t svm_avic_capabs;

void
svm_avic_probe(void)
{
	struct cpuid_regs regs = {
		.cp_eax = 0x8000000a,
	};
	(void) __cpuid_insn(&regs);

	svm_avic_capabs = SAC_NONE;
	if ((regs.cp_edx & CPUID_AMD_EDX_AVIC) == 0) {
		/*
		 * Linux reports that while AVIC is masked out of CPUID on Zen 3
		 * chips, that it _is_ functional if forced on.  We could
		 * consider making that an option for consumers.
		 *
		 * In the mean time, do the prudent thing and report a total
		 * lack of AVIC capability.
		 */
		return;
	}

	svm_avic_capabs = SAC_AVIC;
	if ((regs.cp_edx & CPUID_AMD_EDX_X2AVIC) != 0) {
		svm_avic_capabs |= SAC_X2AVIC;
	}
	if ((regs.cp_edx & CPUID_AMD_EDX_AVIC_LVT) != 0) {
		svm_avic_capabs |= SAC_LVT_ACCESS;
	}

	switch (uarchrev_uarch(cpuid_getuarchrev(CPU))) {
	case X86_UARCH_AMD_ZEN1:
	case X86_UARCH_AMD_ZENPLUS:
	case X86_UARCH_AMD_ZEN2:
		/*
		 * Erratum 1235 (applicable to Zen 1-2) notes that checks of the
		 * IsRunning bit can be unreliable, causing the potential for
		 * missed exits/wake-ups when using IPI virtualization.
		 */
		svm_avic_capabs |= SAC_ERRATA_IPI;
		break;
	default:
		break;
	}
}

vcpu_notify_t
svm_avic_set_intr_ready(struct vlapic *vlapic, uint8_t vector, bool level)
{
	vlapic_set_irr(vlapic, vector, level);

	return (VCPU_NOTIFY_DOORBELL);
}

bool
svm_avic_notify_doorbell(struct vlapic *vlapic)
{
	/* TODO determine if vCPU is running and use doorbell instead */

	/* Fall back to vCPU exit until then */
	return (false);
}

void
svm_vlapic_set_tpr(struct vlapic *vlapic, uint8_t new_tpr)
{
	struct svm_vlapic_state *svs = vlapic_to_svs(vlapic);

	if (svs->svs_avic_flags & SAF_AVIC_ACTIVE) {
		/*
		 * TPR state lives solely in the APIC page while AVIC is active,
		 * and V_TPR contents are ignored.
		 */
		return;
	}

	/*
	 * The guest can modify the TPR by writing to %cr8. In guest mode the
	 * CPU reflects this write to V_TPR without hypervisor intervention.
	 *
	 * The guest can also modify the TPR by writing to it via the memory
	 * mapped APIC page. In this case, the write will be emulated by the
	 * hypervisor.  Keep V_TPR in sync when this occurs.
	 */
	struct svm_softc *sc = svs->svs_softc;
	struct vmcb_ctrl *ctrl  = svm_get_vmcb_ctrl(sc, vlapic->vcpuid);
	const uint8_t v_tpr = new_tpr >> 4;
	if (ctrl->v_tpr != v_tpr) {
		ctrl->v_tpr = v_tpr;
		svm_set_dirty(sc, vlapic->vcpuid, VMCB_CACHE_TPR);
	}
}

void
svm_vlapic_init(void *arg, int vcpuid, struct vlapic *vlapic)
{
	struct svm_softc *sc = arg;
	struct svm_vlapic_state *svs = vlapic_to_svs(vlapic);

	svs->svs_softc = sc;

	vlapic->ops.set_tpr = svm_vlapic_set_tpr;
	vlapic->ops.set_intr_ready = svm_avic_set_intr_ready;
}
