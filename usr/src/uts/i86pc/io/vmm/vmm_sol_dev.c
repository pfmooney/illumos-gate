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
 * Copyright 2015 Pluribus Networks Inc.
 * Copyright 2017 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/cpuvar.h>
#include <sys/ioccom.h>
#include <sys/stat.h>
#include <sys/vmsystm.h>
#include <sys/ddi.h>
#include <sys/mkdev.h>
#include <sys/sunddi.h>
#include <sys/fs/dv_node.h>
#include <sys/pc_hvm.h>
#include <sys/cpuset.h>
#include <sys/id_space.h>

#include <sys/vmm.h>
#include <sys/vmm_instruction_emul.h>
#include <sys/vmm_dev.h>
#include <sys/vmm_impl.h>

#include <vm/vm.h>
#include <vm/seg_dev.h>

#include "io/vatpic.h"
#include "io/vioapic.h"
#include "io/vrtc.h"
#include "io/vhpet.h"
#include "vmm_lapic.h"
#include "vmm_stat.h"
#include "vm/vm_glue.h"

static dev_info_t *vmm_dip;
static void *vmm_statep;

static kmutex_t		vmmdev_mtx;
static list_t		vmmdev_list;
static id_space_t	*vmmdev_minors;
static uint_t		vmmdev_inst_count = 0;
static boolean_t	vmmdev_load_failure;

static const char *vmmdev_hvm_name = "bhyve";

/*
 * vmm trace ring
 */
int	vmm_dmsg_ring_size = VMM_DMSG_RING_SIZE;
static	vmm_trace_rbuf_t *vmm_debug_rbuf;
static	vmm_trace_dmsg_t *vmm_trace_dmsg_alloc(void);
static	void vmm_trace_dmsg_free(void);
static	void vmm_trace_rbuf_alloc(void);
#if notyet
static	void vmm_trace_rbuf_free(void);
#endif

/*
 * This routine is used to manage debug messages
 * on ring buffer.
 */
static vmm_trace_dmsg_t *
vmm_trace_dmsg_alloc(void)
{
	vmm_trace_dmsg_t *dmsg_alloc, *dmsg = vmm_debug_rbuf->dmsgp;

	if (vmm_debug_rbuf->looped == TRUE) {
		vmm_debug_rbuf->dmsgp = dmsg->next;
		return (vmm_debug_rbuf->dmsgp);
	}

	/*
	 * If we're looping for the first time,
	 * connect the ring.
	 */
	if (((vmm_debug_rbuf->size + (sizeof (vmm_trace_dmsg_t))) >
	    vmm_debug_rbuf->maxsize) && (vmm_debug_rbuf->dmsgh != NULL)) {
		dmsg->next = vmm_debug_rbuf->dmsgh;
		vmm_debug_rbuf->dmsgp = vmm_debug_rbuf->dmsgh;
		vmm_debug_rbuf->looped = TRUE;
		return (vmm_debug_rbuf->dmsgp);
	}

	/* If we've gotten this far then memory allocation is needed */
	dmsg_alloc = kmem_zalloc(sizeof (vmm_trace_dmsg_t), KM_NOSLEEP);
	if (dmsg_alloc == NULL) {
		vmm_debug_rbuf->allocfailed++;
		return (dmsg_alloc);
	} else {
		vmm_debug_rbuf->size += sizeof (vmm_trace_dmsg_t);
	}

	if (vmm_debug_rbuf->dmsgp != NULL) {
		dmsg->next = dmsg_alloc;
		vmm_debug_rbuf->dmsgp = dmsg->next;
		return (vmm_debug_rbuf->dmsgp);
	} else {
		/*
		 * We should only be here if we're initializing
		 * the ring buffer.
		 */
		if (vmm_debug_rbuf->dmsgh == NULL) {
			vmm_debug_rbuf->dmsgh = dmsg_alloc;
		} else {
			/* Something is wrong */
			kmem_free(dmsg_alloc, sizeof (vmm_trace_dmsg_t));
			return (NULL);
		}

		vmm_debug_rbuf->dmsgp = dmsg_alloc;
		return (vmm_debug_rbuf->dmsgp);
	}
}

/*
 * Free all messages on debug ring buffer.
 */
static void
vmm_trace_dmsg_free(void)
{
	vmm_trace_dmsg_t *dmsg_next, *dmsg = vmm_debug_rbuf->dmsgh;

	while (dmsg != NULL) {
		dmsg_next = dmsg->next;
		kmem_free(dmsg, sizeof (vmm_trace_dmsg_t));

		/*
		 * If we've looped around the ring than we're done.
		 */
		if (dmsg_next == vmm_debug_rbuf->dmsgh) {
			break;
		} else {
			dmsg = dmsg_next;
		}
	}
}

static void
vmm_trace_rbuf_alloc(void)
{
	vmm_debug_rbuf = kmem_zalloc(sizeof (vmm_trace_rbuf_t), KM_SLEEP);

	mutex_init(&vmm_debug_rbuf->lock, NULL, MUTEX_DRIVER, NULL);

	if (vmm_dmsg_ring_size > 0) {
		vmm_debug_rbuf->maxsize = vmm_dmsg_ring_size;
	}
}

#if notyet
static void
vmm_trace_rbuf_free(void)
{
	vmm_trace_dmsg_free();
	mutex_destroy(&vmm_debug_rbuf->lock);
	kmem_free(vmm_debug_rbuf, sizeof (vmm_trace_rbuf_t));
}
#endif

static void
vmm_vtrace_log(const char *fmt, va_list ap)
{
	vmm_trace_dmsg_t *dmsg;

	if (vmm_debug_rbuf == NULL) {
		return;
	}

	/*
	 * If max size of ring buffer is smaller than size
	 * required for one debug message then just return
	 * since we have no room for the debug message.
	 */
	if (vmm_debug_rbuf->maxsize < (sizeof (vmm_trace_dmsg_t))) {
		return;
	}

	mutex_enter(&vmm_debug_rbuf->lock);

	/* alloc or reuse on ring buffer */
	dmsg = vmm_trace_dmsg_alloc();

	if (dmsg == NULL) {
		/* resource allocation failed */
		mutex_exit(&vmm_debug_rbuf->lock);
		return;
	}

	gethrestime(&dmsg->timestamp);

	(void) vsnprintf(dmsg->buf, sizeof (dmsg->buf), fmt, ap);

	mutex_exit(&vmm_debug_rbuf->lock);
}

void
vmm_trace_log(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vmm_vtrace_log(fmt, ap);
	va_end(ap);
}

void
vmmdev_init(void)
{
	vmm_trace_rbuf_alloc();
}

int
vmmdev_cleanup(void)
{
	VERIFY(list_is_empty(&vmmdev_list));

	vmm_trace_dmsg_free();
	return (0);
}

static int
vmmdev_get_memseg(vmm_softc_t *sc, struct vm_memseg *mseg)
{
	int error;
	bool sysmem;

	error = vm_get_memseg(sc->vmm_vm, mseg->segid, &mseg->len, &sysmem,
	    NULL);
	if (error || mseg->len == 0)
		return (error);

	if (!sysmem) {
		vmm_devmem_entry_t *de;
		list_t *dl = &sc->vmm_devmem_list;

		for (de = list_head(dl); de != NULL; de = list_next(dl, de)) {
			if (de->vde_segid == mseg->segid) {
				break;
			}
		}
		if (de != NULL) {
			(void) strlcpy(mseg->name, de->vde_name,
			    sizeof (de->vde_name));
		}
	} else {
		bzero(mseg->name, sizeof (mseg->name));
	}

	return (error);
}

/*
 * The 'devmem' hack:
 *
 * On native FreeBSD, bhyve consumers are allowed to create 'devmem' segments
 * in the vm which appear with their own name related to the vm under /dev.
 * Since this would be a hassle from an sdev perspective and would require a
 * new cdev interface (or complicate the existing one), we choose to implement
 * this in a different manner.  When 'devmem' mappings are created, an
 * identifying off_t is communicated back out to userspace.  That off_t,
 * residing above the normal guest memory space, can be used to mmap the
 * 'devmem' mapping from the already-open vm device.
 */

static int
vmmdev_devmem_create(vmm_softc_t *sc, struct vm_memseg *mseg, const char *name)
{
	off_t map_offset;
	vmm_devmem_entry_t *entry;

	if (list_is_empty(&sc->vmm_devmem_list)) {
		map_offset = VM_DEVMEM_START;
	} else {
		entry = list_tail(&sc->vmm_devmem_list);
		map_offset = entry->vde_off + entry->vde_len;
		if (map_offset < entry->vde_off) {
			/* Do not tolerate overflow */
			return (ERANGE);
		}
		/*
		 * XXXJOY: We could choose to search the list for duplicate
		 * names and toss an error.  Since we're using the offset
		 * method for now, it does not make much of a difference.
		 */
	}

	entry = kmem_zalloc(sizeof (*entry), KM_SLEEP);
	entry->vde_segid = mseg->segid;
	entry->vde_len = mseg->len;
	entry->vde_off = map_offset;
	(void) strlcpy(entry->vde_name, name, sizeof (entry->vde_name));
	list_insert_tail(&sc->vmm_devmem_list, entry);

	return (0);
}

static boolean_t
vmmdev_devmem_segid(vmm_softc_t *sc, off_t off, off_t len, int *segidp)
{
	list_t *dl = &sc->vmm_devmem_list;
	vmm_devmem_entry_t *de = NULL;

	VERIFY(off >= VM_DEVMEM_START);

	for (de = list_head(dl); de != NULL; de = list_next(dl, de)) {
		/* XXX: Only hit on direct offset/length matches for now */
		if (de->vde_off == off && de->vde_len == len) {
			break;
		}
	}
	if (de == NULL) {
		return (B_FALSE);
	}

	*segidp = de->vde_segid;
	return (B_TRUE);
}

static void
vmmdev_devmem_purge(vmm_softc_t *sc)
{
	vmm_devmem_entry_t *entry;

	while ((entry = list_remove_head(&sc->vmm_devmem_list)) != NULL) {
		kmem_free(entry, sizeof (*entry));
	}
}

static int
vmmdev_alloc_memseg(vmm_softc_t *sc, struct vm_memseg *mseg)
{
	int error;
	bool sysmem = true;

	if (VM_MEMSEG_NAME(mseg)) {
		sysmem = false;
	}
	error = vm_alloc_memseg(sc->vmm_vm, mseg->segid, mseg->len, sysmem);

	if (error == 0 && VM_MEMSEG_NAME(mseg)) {
		/*
		 * Rather than create a whole fresh device from which userspace
		 * can mmap this segment, instead make it available at an
		 * offset above where the main guest memory resides.
		 */
		error = vmmdev_devmem_create(sc, mseg, mseg->name);
		if (error != 0) {
			vm_free_memseg(sc->vmm_vm, mseg->segid);
		}
	}
	return (error);
}


static int
vcpu_lock_one(vmm_softc_t *sc, int vcpu)
{
	int error;

	if (vcpu < 0 || vcpu >= VM_MAXCPU)
		return (EINVAL);

	error = vcpu_set_state(sc->vmm_vm, vcpu, VCPU_FROZEN, true);
	return (error);
}

static void
vcpu_unlock_one(vmm_softc_t *sc, int vcpu)
{
	enum vcpu_state state;

	state = vcpu_get_state(sc->vmm_vm, vcpu, NULL);
	if (state != VCPU_FROZEN) {
		panic("vcpu %s(%d) has invalid state %d", vm_name(sc->vmm_vm),
		    vcpu, state);
	}

	vcpu_set_state(sc->vmm_vm, vcpu, VCPU_IDLE, false);
}

static int
vcpu_lock_all(vmm_softc_t *sc)
{
	int error, vcpu;

	for (vcpu = 0; vcpu < VM_MAXCPU; vcpu++) {
		error = vcpu_lock_one(sc, vcpu);
		if (error)
			break;
	}

	if (error) {
		while (--vcpu >= 0)
			vcpu_unlock_one(sc, vcpu);
	}

	return (error);
}

static void
vcpu_unlock_all(vmm_softc_t *sc)
{
	int vcpu;

	for (vcpu = 0; vcpu < VM_MAXCPU; vcpu++)
		vcpu_unlock_one(sc, vcpu);
}

int
vmmdev_do_ioctl(vmm_softc_t *sc, int cmd, intptr_t arg, int md,
    cred_t *credp, int *rvalp)
{
	int error, vcpu, state_changed, size, pincount;
	void *datap = (void *)arg;
	struct vm_register vmreg;
	struct vm_seg_desc vmsegd;
	struct vm_run vmrun;
	struct vm_exception vmexc;
	struct vm_lapic_irq vmirq;
	struct vm_lapic_msi vmmsi;
	struct vm_ioapic_irq ioapic_irq;
	struct vm_isa_irq isa_irq;
	struct vm_isa_irq_trigger isa_irq_trigger;
	struct vm_capability vmcap;
	struct vm_pptdev *pptdev;
	struct vm_pptdev_mmio *pptmmio;
	struct vm_pptdev_msi *pptmsi;
	struct vm_pptdev_msix *pptmsix;
	struct vm_nmi vmnmi;
	struct vm_stats vmstats;
	struct vm_stat_desc statdesc;
	struct vm_x2apic x2apic;
	struct vm_gpa_pte gpapte;
	struct vm_suspend vmsuspend;
	struct vm_gla2gpa gg;
	struct vm_activate_cpu vac;
	struct vm_cpuset vm_cpuset;
	struct vm_intinfo vmii;
	struct vm_rtc_time rtctime;
	struct vm_rtc_data rtcdata;
	struct vm_memmap mm;
	struct vm_memseg vmseg;
	struct vm_hpet_cap hpetcap;

	vcpu = -1;
	state_changed = 0;
	error = 0;

	/*
	 * Some VMM ioctls can operate only on vcpus that are not running.
	 */
	switch (cmd) {
	case VM_RUN:
	case VM_GET_REGISTER:
	case VM_SET_REGISTER:
	case VM_GET_SEGMENT_DESCRIPTOR:
	case VM_SET_SEGMENT_DESCRIPTOR:
	case VM_INJECT_EXCEPTION:
	case VM_GET_CAPABILITY:
	case VM_SET_CAPABILITY:
	case VM_PPTDEV_MSI:
	case VM_PPTDEV_MSIX:
	case VM_SET_X2APIC_STATE:
	case VM_GLA2GPA:
	case VM_ACTIVATE_CPU:
	case VM_SET_INTINFO:
	case VM_GET_INTINFO:
	case VM_RESTART_INSTRUCTION:
		/*
		 * XXX fragile, handle with care
		 * Assumes that the first field of the ioctl data is the vcpu.
		 */
		if (ddi_copyin(datap, &vcpu, sizeof (vcpu), md)) {
			return (EFAULT);
		}
		if (vcpu < 0 || vcpu >= VM_MAXCPU) {
			error = EINVAL;
			goto done;
		}

		error = vcpu_lock_one(sc, vcpu);
		if (error)
			goto done;
		state_changed = 1;
		break;

	case VM_MAP_PPTDEV_MMIO:
	case VM_BIND_PPTDEV:
	case VM_UNBIND_PPTDEV:
	case VM_ALLOC_MEMSEG:
	case VM_MMAP_MEMSEG:
	case VM_REINIT:
		/*
		 * ioctls that operate on the entire virtual machine must
		 * prevent all vcpus from running.
		 */
		error = vcpu_lock_all(sc);
		if (error)
			goto done;
		state_changed = 2;
		break;

	case VM_GET_MEMSEG:
	case VM_MMAP_GETNEXT:
#ifndef __FreeBSD__
	case VM_DEVMEM_GETOFFSET:
#endif
		/*
		 * Lock a vcpu to make sure that the memory map cannot be
		 * modified while it is being inspected.
		 */
		vcpu = VM_MAXCPU - 1;
		error = vcpu_lock_one(sc, vcpu);
		if (error)
			goto done;
		state_changed = 1;
		break;

	default:
		break;
	}

	switch (cmd) {
	case VM_RUN:
		if (ddi_copyin(datap, &vmrun, sizeof (vmrun), md)) {
			error = EFAULT;
			break;
		}
		error = vm_run(sc->vmm_vm, &vmrun);
		/*
		 * XXXJOY: I think it's necessary to do copyout, even in the
		 * face of errors, since the exit state is communicated out.
		 */
		if (ddi_copyout(&vmrun, datap, sizeof (vmrun), md)) {
			error = EFAULT;
			break;
		}
		break;
	case VM_SUSPEND:
		if (ddi_copyin(datap, &vmsuspend, sizeof (vmsuspend), md)) {
			error = EFAULT;
			break;
		}
		error = vm_suspend(sc->vmm_vm, vmsuspend.how);
		break;
	case VM_REINIT:
		error = vm_reinit(sc->vmm_vm);
		break;
	case VM_STAT_DESC: {
		if (ddi_copyin(datap, &statdesc, sizeof (statdesc), md)) {
			error = EFAULT;
			break;
		}
		error = vmm_stat_desc_copy(statdesc.index, statdesc.desc,
		    sizeof (statdesc.desc));
		if (error == 0 &&
		    ddi_copyout(&statdesc, datap, sizeof (statdesc), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_STATS_IOC: {
		CTASSERT(MAX_VM_STATS >= MAX_VMM_STAT_ELEMS);
		if (ddi_copyin(datap, &vmstats, sizeof (vmstats), md)) {
			error = EFAULT;
			break;
		}
		hrt2tv(gethrtime(), &vmstats.tv);
		error = vmm_stat_copy(sc->vmm_vm, vmstats.cpuid,
		    &vmstats.num_entries, vmstats.statbuf);
		if (error == 0 &&
		    ddi_copyout(&vmstats, datap, sizeof (vmstats), md)) {
			error = EFAULT;
			break;
		}
		break;
	}

	/* XXXJOY: punt on these for now */
	case VM_PPTDEV_MSI:
		if (ddi_copyin(datap, &pptmsi, sizeof (pptmsi), md)) {
			error = EFAULT;
			break;
		}
		return (ENOTTY);
	case VM_PPTDEV_MSIX:
		if (ddi_copyin(datap, &pptmsix, sizeof (pptmsix), md)) {
			error = EFAULT;
			break;
		}
		return (ENOTTY);
	case VM_MAP_PPTDEV_MMIO:
		if (ddi_copyin(datap, &pptmmio, sizeof (pptmmio), md)) {
			error = EFAULT;
			break;
		}
		return (ENOTTY);
	case VM_BIND_PPTDEV:
	case VM_UNBIND_PPTDEV:
		if (ddi_copyin(datap, &pptdev, sizeof (pptdev), md)) {
			error = EFAULT;
			break;
		}
		return (ENOTTY);

	case VM_INJECT_EXCEPTION:
		if (ddi_copyin(datap, &vmexc, sizeof (vmexc), md)) {
			error = EFAULT;
			break;
		}
		error = vm_inject_exception(sc->vmm_vm, vmexc.cpuid,
		    vmexc.vector, vmexc.error_code_valid, vmexc.error_code,
		    vmexc.restart_instruction);
		break;
	case VM_INJECT_NMI:
		if (ddi_copyin(datap, &vmnmi, sizeof (vmnmi), md)) {
			error = EFAULT;
			break;
		}
		error = vm_inject_nmi(sc->vmm_vm, vmnmi.cpuid);
		break;
	case VM_LAPIC_IRQ:
		if (ddi_copyin(datap, &vmirq, sizeof (vmirq), md)) {
			error = EFAULT;
			break;
		}
		error = lapic_intr_edge(sc->vmm_vm, vmirq.cpuid, vmirq.vector);
		break;
	case VM_LAPIC_LOCAL_IRQ:
		if (ddi_copyin(datap, &vmirq, sizeof (vmirq), md)) {
			error = EFAULT;
			break;
		}
		error = lapic_set_local_intr(sc->vmm_vm, vmirq.cpuid,
		    vmirq.vector);
		break;
	case VM_LAPIC_MSI:
		if (ddi_copyin(datap, &vmmsi, sizeof (vmmsi), md)) {
			error = EFAULT;
			break;
		}
		error = lapic_intr_msi(sc->vmm_vm, vmmsi.addr, vmmsi.msg);
		break;
	case VM_IOAPIC_ASSERT_IRQ:
		if (ddi_copyin(datap, &ioapic_irq, sizeof (ioapic_irq), md)) {
			error = EFAULT;
			break;
		}
		error = vioapic_assert_irq(sc->vmm_vm, ioapic_irq.irq);
		break;
	case VM_IOAPIC_DEASSERT_IRQ:
		if (ddi_copyin(datap, &ioapic_irq, sizeof (ioapic_irq), md)) {
			error = EFAULT;
			break;
		}
		error = vioapic_deassert_irq(sc->vmm_vm, ioapic_irq.irq);
		break;
	case VM_IOAPIC_PULSE_IRQ:
		if (ddi_copyin(datap, &ioapic_irq, sizeof (ioapic_irq), md)) {
			error = EFAULT;
			break;
		}
		error = vioapic_pulse_irq(sc->vmm_vm, ioapic_irq.irq);
		break;
	case VM_IOAPIC_PINCOUNT:
		pincount = vioapic_pincount(sc->vmm_vm);
		if (ddi_copyout(&pincount, datap, sizeof (int), md)) {
			error = EFAULT;
			break;
		}
		break;
	case VM_ISA_ASSERT_IRQ:
		if (ddi_copyin(datap, &isa_irq, sizeof (isa_irq), md)) {
			error = EFAULT;
			break;
		}
		error = vatpic_assert_irq(sc->vmm_vm, isa_irq.atpic_irq);
		if (error == 0 && isa_irq.ioapic_irq != -1) {
			error = vioapic_assert_irq(sc->vmm_vm,
			    isa_irq.ioapic_irq);
		}
		break;
	case VM_ISA_DEASSERT_IRQ:
		if (ddi_copyin(datap, &isa_irq, sizeof (isa_irq), md)) {
			error = EFAULT;
			break;
		}
		error = vatpic_deassert_irq(sc->vmm_vm, isa_irq.atpic_irq);
		if (error == 0 && isa_irq.ioapic_irq != -1) {
			error = vioapic_deassert_irq(sc->vmm_vm,
			    isa_irq.ioapic_irq);
		}
		break;
	case VM_ISA_PULSE_IRQ:
		if (ddi_copyin(datap, &isa_irq, sizeof (isa_irq), md)) {
			error = EFAULT;
			break;
		}
		error = vatpic_pulse_irq(sc->vmm_vm, isa_irq.atpic_irq);
		if (error == 0 && isa_irq.ioapic_irq != -1) {
			error = vioapic_pulse_irq(sc->vmm_vm,
			    isa_irq.ioapic_irq);
		}
		break;
	case VM_ISA_SET_IRQ_TRIGGER:
		if (ddi_copyin(datap, &isa_irq_trigger,
		    sizeof (isa_irq_trigger), md)) {
			error = EFAULT;
			break;
		}
		error = vatpic_set_irq_trigger(sc->vmm_vm,
		    isa_irq_trigger.atpic_irq, isa_irq_trigger.trigger);
		break;
	case VM_MMAP_GETNEXT:
		if (ddi_copyin(datap, &mm, sizeof (mm), md)) {
			error = EFAULT;
			break;
		}
		error = vm_mmap_getnext(sc->vmm_vm, &mm.gpa, &mm.segid,
		    &mm.segoff, &mm.len, &mm.prot, &mm.flags);
		if (error == 0 && ddi_copyout(&mm, datap, sizeof (mm), md)) {
			error = EFAULT;
			break;
		}
		break;
	case VM_MMAP_MEMSEG:
		if (ddi_copyin(datap, &mm, sizeof (mm), md)) {
			error = EFAULT;
			break;
		}
		error = vm_mmap_memseg(sc->vmm_vm, mm.gpa, mm.segid, mm.segoff,
		    mm.len, mm.prot, mm.flags);
		break;
	case VM_ALLOC_MEMSEG:
		if (ddi_copyin(datap, &vmseg, sizeof (vmseg), md)) {
			error = EFAULT;
			break;
		}
		error = vmmdev_alloc_memseg(sc, &vmseg);
		break;
	case VM_GET_MEMSEG:
		if (ddi_copyin(datap, &vmseg, sizeof (vmseg), md)) {
			error = EFAULT;
			break;
		}
		error = vmmdev_get_memseg(sc, &vmseg);
		if (error == 0 &&
		    ddi_copyout(&vmseg, datap, sizeof (vmseg), md)) {
			error = EFAULT;
			break;
		}
		break;
	case VM_GET_REGISTER:
		if (ddi_copyin(datap, &vmreg, sizeof (vmreg), md)) {
			error = EFAULT;
			break;
		}
		error = vm_get_register(sc->vmm_vm, vmreg.cpuid, vmreg.regnum,
		    &vmreg.regval);
		if (error == 0 &&
		    ddi_copyout(&vmreg, datap, sizeof (vmreg), md)) {
			error = EFAULT;
			break;
		}
		break;
	case VM_SET_REGISTER:
		if (ddi_copyin(datap, &vmreg, sizeof (vmreg), md)) {
			error = EFAULT;
			break;
		}
		error = vm_set_register(sc->vmm_vm, vmreg.cpuid, vmreg.regnum,
		    vmreg.regval);
		break;
	case VM_SET_SEGMENT_DESCRIPTOR:
		if (ddi_copyin(datap, &vmsegd, sizeof (vmsegd), md)) {
			error = EFAULT;
			break;
		}
		error = vm_set_seg_desc(sc->vmm_vm, vmsegd.cpuid,
		    vmsegd.regnum, &vmsegd.desc);
		break;
	case VM_GET_SEGMENT_DESCRIPTOR:
		if (ddi_copyin(datap, &vmsegd, sizeof (vmsegd), md)) {
			error = EFAULT;
			break;
		}
		error = vm_get_seg_desc(sc->vmm_vm, vmsegd.cpuid,
		    vmsegd.regnum, &vmsegd.desc);
		if (error == 0 &&
		    ddi_copyout(&vmsegd, datap, sizeof (vmsegd), md)) {
			error = EFAULT;
			break;
		}
		break;
	case VM_GET_CAPABILITY:
		if (ddi_copyin(datap, &vmcap, sizeof (vmcap), md)) {
			error = EFAULT;
			break;
		}
		error = vm_get_capability(sc->vmm_vm, vmcap.cpuid,
		    vmcap.captype, &vmcap.capval);
		if (error == 0 &&
		    ddi_copyout(&vmcap, datap, sizeof (vmcap), md)) {
			error = EFAULT;
			break;
		}
		break;
	case VM_SET_CAPABILITY:
		if (ddi_copyin(datap, &vmcap, sizeof (vmcap), md)) {
			error = EFAULT;
			break;
		}
		error = vm_set_capability(sc->vmm_vm, vmcap.cpuid,
		    vmcap.captype, vmcap.capval);
		break;
	case VM_SET_X2APIC_STATE:
		if (ddi_copyin(datap, &x2apic, sizeof (x2apic), md)) {
			error = EFAULT;
			break;
		}
		error = vm_set_x2apic_state(sc->vmm_vm, x2apic.cpuid,
		    x2apic.state);
		break;
	case VM_GET_X2APIC_STATE:
		if (ddi_copyin(datap, &x2apic, sizeof (x2apic), md)) {
			error = EFAULT;
			break;
		}
		error = vm_get_x2apic_state(sc->vmm_vm, x2apic.cpuid,
		    &x2apic.state);
		if (error == 0 &&
		    ddi_copyout(&x2apic, datap, sizeof (x2apic), md)) {
			error = EFAULT;
			break;
		}
		break;
	case VM_GET_GPA_PMAP:
		if (ddi_copyin(datap, &gpapte, sizeof (gpapte), md)) {
			error = EFAULT;
			break;
		}
#ifdef __FreeBSD__
		/* XXXJOY: add function? */
		pmap_get_mapping(vmspace_pmap(vm_get_vmspace(sc->vmm_vm)),
		    gpapte.gpa, gpapte.pte, &gpapte.ptenum);
#endif
		error = 0;
		break;
	case VM_GET_HPET_CAPABILITIES:
		error = vhpet_getcap(&hpetcap);
		if (error == 0 &&
		    ddi_copyout(&hpetcap, datap, sizeof (hpetcap), md)) {
			error = EFAULT;
			break;
		}
		break;
	case VM_GLA2GPA: {
		CTASSERT(PROT_READ == VM_PROT_READ);
		CTASSERT(PROT_WRITE == VM_PROT_WRITE);
		CTASSERT(PROT_EXEC == VM_PROT_EXECUTE);

		if (ddi_copyin(datap, &gg, sizeof (gg), md)) {
			error = EFAULT;
			break;
		}
		error = vm_gla2gpa(sc->vmm_vm, gg.vcpuid, &gg.paging, gg.gla,
		    gg.prot, &gg.gpa, &gg.fault);
		KASSERT(error == 0 || error == EFAULT,
		    ("%s: vm_gla2gpa unknown error %d", __func__, error));
		if (error == 0 && ddi_copyout(&gg, datap, sizeof (gg), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_ACTIVATE_CPU:
		if (ddi_copyin(datap, &vac, sizeof (vac), md)) {
			error = EFAULT;
			break;
		}
		error = vm_activate_cpu(sc->vmm_vm, vac.vcpuid);
		break;

	case VM_GET_CPUS: {
		cpuset_t tempset;
		void *srcp = &tempset;

		if (ddi_copyin(datap, &vm_cpuset, sizeof (vm_cpuset), md)) {
			error = EFAULT;
			break;
		}

		/* Be more generous about sizing since our cpuset_t is large. */
		size = vm_cpuset.cpusetsize;
		if (size <= 0 || size > sizeof (cpuset_t)) {
			error = ERANGE;
		}
		/*
		 * If they want a ulong_t or less, make sure they receive the
		 * low bits with all the useful information.
		 */
		if (size <= tempset.cpub[0]) {
			srcp = &tempset.cpub[0];
		}

		if (vm_cpuset.which == VM_ACTIVE_CPUS) {
			tempset = vm_active_cpus(sc->vmm_vm);
		} else if (vm_cpuset.which == VM_SUSPENDED_CPUS) {
			tempset = vm_suspended_cpus(sc->vmm_vm);
		} else {
			error = EINVAL;
		}

		ASSERT(size > 0 && size <= sizeof (tempset));
		if (error == 0 &&
		    ddi_copyout(&tempset, vm_cpuset.cpus, size, md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_SET_INTINFO:
		if (ddi_copyin(datap, &vmii, sizeof (vmii), md)) {
			error = EFAULT;
			break;
		}
		error = vm_exit_intinfo(sc->vmm_vm, vmii.vcpuid, vmii.info1);
		break;
	case VM_GET_INTINFO:
		if (ddi_copyin(datap, &vmii, sizeof (vmii), md)) {
			error = EFAULT;
			break;
		}
		error = vm_get_intinfo(sc->vmm_vm, vmii.vcpuid, &vmii.info1,
		    &vmii.info2);
		if (error == 0 &&
		    ddi_copyout(&vmii, datap, sizeof (vmii), md)) {
			error = EFAULT;
			break;
		}
		break;
	case VM_RTC_WRITE:
		if (ddi_copyin(datap, &rtcdata, sizeof (rtcdata), md)) {
			error = EFAULT;
			break;
		}
		error = vrtc_nvram_write(sc->vmm_vm, rtcdata.offset,
		    rtcdata.value);
		break;
	case VM_RTC_READ:
		if (ddi_copyin(datap, &rtcdata, sizeof (rtcdata), md)) {
			error = EFAULT;
			break;
		}
		error = vrtc_nvram_read(sc->vmm_vm, rtcdata.offset,
		    &rtcdata.value);
		if (error == 0 &&
		    ddi_copyout(&rtcdata, datap, sizeof (rtcdata), md)) {
			error = EFAULT;
			break;
		}
		break;
	case VM_RTC_SETTIME:
		if (ddi_copyin(datap, &rtctime, sizeof (rtctime), md)) {
			error = EFAULT;
			break;
		}
		error = vrtc_set_time(sc->vmm_vm, rtctime.secs);
		break;
	case VM_RTC_GETTIME:
		rtctime.secs = vrtc_get_time(sc->vmm_vm);
		if (ddi_copyout(&rtctime, datap, sizeof (rtctime), md)) {
			error = EFAULT;
			break;
		}
		break;

	case VM_RESTART_INSTRUCTION:
		error = vm_restart_instruction(sc->vmm_vm, vcpu);
		break;
#ifndef __FreeBSD__
	case VM_DEVMEM_GETOFFSET: {
		struct vm_devmem_offset vdo;
		list_t *dl = &sc->vmm_devmem_list;
		vmm_devmem_entry_t *de = NULL;

		if (ddi_copyin(datap, &vdo, sizeof (vdo), md) != 0) {
			error = EFAULT;
			break;
		}

		for (de = list_head(dl); de != NULL; de = list_next(dl, de)) {
			if (de->vde_segid == vdo.segid) {
				break;
			}
		}
		if (de != NULL) {
			vdo.offset = de->vde_off;
			if (ddi_copyout(&vdo, datap, sizeof (vdo), md) != 0) {
				error = EFAULT;
			}
		} else {
			error = ENOENT;
		}
	}
		break;
#endif
	default:
		error = ENOTTY;
		break;
	}

	if (state_changed == 1) {
		vcpu_unlock_one(sc, vcpu);
	} else if (state_changed == 2) {
		vcpu_unlock_all(sc);
	}

done:
	/* Make sure that no handler returns a bogus value like ERESTART */
	KASSERT(error >= 0, ("vmmdev_ioctl: invalid error return %d", error));
	return (error);
}

static boolean_t
vmmdev_mod_incr()
{
	ASSERT(MUTEX_HELD(&vmmdev_mtx));

	if (vmmdev_inst_count == 0) {
		/*
		 * If the HVM portions of the module failed initialize on a
		 * previous attempt, do not bother with a retry.  This tracker
		 * is cleared on module attach, allowing subsequent attempts if
		 * desired by the user.
		 */
		if (vmmdev_load_failure) {
			return (B_FALSE);
		}

		if (!hvm_excl_hold(vmmdev_hvm_name)) {
			return (B_FALSE);
		}
		if (vmm_mod_load() != 0) {
			hvm_excl_rele(vmmdev_hvm_name);
			vmmdev_load_failure = B_TRUE;
			return (B_FALSE);
		}
	}

	vmmdev_inst_count++;
	return (B_TRUE);
}

static void
vmmdev_mod_decr(void)
{
	ASSERT(MUTEX_HELD(&vmmdev_mtx));
	ASSERT(vmmdev_inst_count > 0);

	vmmdev_inst_count--;
	if (vmmdev_inst_count == 0) {
		VERIFY0(vmm_mod_unload());
		hvm_excl_rele(vmmdev_hvm_name);
	}
}

static int
vmmdev_do_vm_create(dev_info_t *dip, char *name)
{
	vmm_softc_t	*sc = NULL;
	minor_t		minor;
	int		error = ENOMEM;

	if (strlen(name) >= VM_MAX_NAMELEN) {
		return (EINVAL);
	}

	mutex_enter(&vmmdev_mtx);
	if (!vmmdev_mod_incr()) {
		mutex_exit(&vmmdev_mtx);
		return (ENXIO);
	}

	/* Look for duplicates names */
	for (sc = list_head(&vmmdev_list); sc != NULL;
	    sc = list_next(&vmmdev_list, sc)) {
		if (strncmp(name, sc->vmm_name, sizeof (sc->vmm_name)) == 0) {
			mutex_exit(&vmmdev_mtx);
			return (EEXIST);
		}
	}

	minor = id_alloc(vmmdev_minors);
	if (ddi_soft_state_zalloc(vmm_statep, minor) != DDI_SUCCESS) {
		goto fail;
	} else if ((sc = ddi_get_soft_state(vmm_statep, minor)) == NULL) {
		ddi_soft_state_free(vmm_statep, minor);
		goto fail;
	} else if (ddi_create_minor_node(dip, name, S_IFCHR, minor,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		goto fail;
	}

	error = vm_create(name, &sc->vmm_vm);
	if (error == 0) {
		/* Complete VM intialization and report success. */
		strcpy(sc->vmm_name, name);
		sc->vmm_minor = minor;
		list_create(&sc->vmm_devmem_list, sizeof (vmm_devmem_entry_t),
		    offsetof(vmm_devmem_entry_t, vde_node));
		list_insert_tail(&vmmdev_list, sc);
		mutex_exit(&vmmdev_mtx);
		return (0);
	}

	ddi_remove_minor_node(dip, name);
fail:
	id_free(vmmdev_minors, minor);
	vmmdev_mod_decr();
	if (sc != NULL) {
		ddi_soft_state_free(vmm_statep, minor);
	}
	mutex_exit(&vmmdev_mtx);
	return (error);
}

static vmm_softc_t *
vmm_lookup(const char *name)
{
	list_t *vml = &vmmdev_list;
	vmm_softc_t *sc;

	ASSERT(MUTEX_HELD(&vmmdev_mtx));

	for (sc = list_head(vml); sc != NULL; sc = list_next(vml, sc)) {
		if (strncmp(sc->vmm_name, name, sizeof (sc->vmm_name)) == 0) {
			break;
		}
	}

	return (sc);
}

struct vm *
vm_lookup_by_name(char *name)
{
#if 0
	vmm_softc_t	*sc;
	/*
	 * XXXJOY: This is racy (since no hold is placed on the vm object) and
	 * should be improved for the viona linkage.
	 */
	mutex_enter(&vmmdev_mtx);

	if ((sc = vmm_lookup(name)) == NULL) {
		mutex_exit(&vmmdev_mtx);
		return (NULL);
	}

	mutex_exit(&vmmdev_mtx);

	return (sc->vmm_vm);
#endif
	return (NULL);
}

static int
vmmdev_do_vm_destroy(dev_info_t *dip, const char *name)
{
	vmm_softc_t	*sc;
	dev_info_t	*pdip = ddi_get_parent(dip);
	minor_t		minor;

	mutex_enter(&vmmdev_mtx);

	if ((sc = vmm_lookup(name)) == NULL) {
		mutex_exit(&vmmdev_mtx);
		return (ENOENT);
	}
	if (sc->vmm_is_open) {
		mutex_exit(&vmmdev_mtx);
		return (EBUSY);
	}

	/* Clean up devmem entries */
	vmmdev_devmem_purge(sc);

	vm_destroy(sc->vmm_vm);
	list_remove(&vmmdev_list, sc);
	ddi_remove_minor_node(dip, sc->vmm_name);
	minor = sc->vmm_minor;
	ddi_soft_state_free(vmm_statep, minor);
	id_free(vmmdev_minors, minor);
	(void) devfs_clean(pdip, NULL, DV_CLEAN_FORCE);
	vmmdev_mod_decr();

	mutex_exit(&vmmdev_mtx);

	return (0);
}


static int
vmm_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	minor_t		minor;
	vmm_softc_t	*sc;

	minor = getminor(*devp);
	if (minor == VMM_CTL_MINOR) {
		/*
		 * Master control device must be opened exclusively.
		 */
		if ((flag & FEXCL) != FEXCL || otyp != OTYP_CHR) {
			return (EINVAL);
		}

		return (0);
	}

	mutex_enter(&vmmdev_mtx);
	sc = ddi_get_soft_state(vmm_statep, minor);
	if (sc == NULL) {
		mutex_exit(&vmmdev_mtx);
		return (ENXIO);
	}

	if (sc->vmm_is_open) {
		mutex_exit(&vmmdev_mtx);
		return (EBUSY);
	}
	sc->vmm_is_open = B_TRUE;
	mutex_exit(&vmmdev_mtx);

	return (0);
}

static int
vmm_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	minor_t		minor;
	vmm_softc_t	*sc;

	minor = getminor(dev);
	if (minor == VMM_CTL_MINOR)
		return (0);

	mutex_enter(&vmmdev_mtx);
	sc = ddi_get_soft_state(vmm_statep, minor);
	if (sc == NULL) {
		mutex_exit(&vmmdev_mtx);
		return (ENXIO);
	}

	sc->vmm_is_open = B_FALSE;
	mutex_exit(&vmmdev_mtx);

	return (0);
}

static int
vmm_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	vmm_softc_t	*sc;
	struct vmm_ioctl	kvi;
	minor_t			minor;

	minor = getminor(dev);

	if (minor == VMM_CTL_MINOR) {
		if (ddi_copyin((void *)arg, &kvi, sizeof (struct vmm_ioctl),
		    mode)) {
			return (EFAULT);
		}
		switch (cmd) {
		case VMM_CREATE_VM:
			if ((mode & FWRITE) == 0)
				return (EPERM);
			return (vmmdev_do_vm_create(vmm_dip, kvi.vmm_name));
		case VMM_DESTROY_VM:
			if ((mode & FWRITE) == 0)
				return (EPERM);
			return (vmmdev_do_vm_destroy(vmm_dip, kvi.vmm_name));
		default:
			break;
		}
	}

	sc = ddi_get_soft_state(vmm_statep, minor);
	ASSERT(sc);

	return (vmmdev_do_ioctl(sc, cmd, arg, mode, credp, rvalp));
}

static int
vmm_segmap(dev_t dev, off_t off, struct as *as, caddr_t *addrp, off_t len,
    unsigned int prot, unsigned int maxprot, unsigned int flags, cred_t *credp)
{
	vmm_softc_t *sc;
	const minor_t minor = getminor(dev);
	struct vm *vm;
	int err;
	vm_object_t vmo = NULL;
	struct vmspace *vms;

	if (minor == VMM_CTL_MINOR) {
		return (ENODEV);
	}
	if (off < 0 || (off + len) <= 0) {
		return (EINVAL);
	}
	if ((prot & PROT_USER) == 0) {
		return (EACCES);
	}

	sc = ddi_get_soft_state(vmm_statep, minor);
	ASSERT(sc);

	/* Get a read lock on the guest memory map by freezing any vcpu. */
	if ((err = vcpu_lock_all(sc)) != 0) {
		return (err);
	}

	vm = sc->vmm_vm;
	vms = vm_get_vmspace(vm);
	if (off >= VM_DEVMEM_START) {
		int segid;

		/* Mapping a devmem "device" */
		if (!vmmdev_devmem_segid(sc, off, len, &segid)) {
			err = ENODEV;
			goto out;
		}
		err = vm_get_memseg(vm, segid, NULL, NULL, &vmo);
		if (err != 0) {
			goto out;
		}
		err = vm_segmap_obj(vms, vmo, as, addrp, prot, maxprot, flags);
	} else {
		/* Mapping a part of the guest physical space */
		err = vm_segmap_space(vms, off, as, addrp, len, prot, maxprot,
		    flags);
	}


out:
	vcpu_unlock_all(sc);
	return (err);
}

static int
vmm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	vmm_sol_glue_init();
	vmmdev_load_failure = B_FALSE;
	vmm_dip = dip;

	/*
	 * Create control node.  Other nodes will be created on demand.
	 */
	if (ddi_create_minor_node(dip, VMM_CTL_MINOR_NODE, S_IFCHR,
	    VMM_CTL_MINOR, DDI_PSEUDO, 0) != 0) {
		return (DDI_FAILURE);
	}

	ddi_report_dev(dip);

	/* XXX: This needs updating */
	vmm_arena_init();

	return (DDI_SUCCESS);
}

static int
vmm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	/* Ensure that all resources have been cleaned up */
	mutex_enter(&vmmdev_mtx);
	if (!list_is_empty(&vmmdev_list) || vmmdev_inst_count != 0) {
		mutex_exit(&vmmdev_mtx);
		return (DDI_FAILURE);
	}
	mutex_exit(&vmmdev_mtx);

	/* XXX: This needs updating */
	if (!vmm_arena_fini()) {
		return (DDI_FAILURE);
	}

	/* Remove the control node. */
	ddi_remove_minor_node(dip, VMM_CTL_MINOR_NODE);
	vmm_dip = NULL;
	vmm_sol_glue_cleanup();

	return (DDI_SUCCESS);
}

static struct cb_ops vmm_cb_ops = {
	vmm_open,
	vmm_close,
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	vmm_ioctl,
	nodev,		/* devmap */
	nodev,		/* mmap */
	vmm_segmap,
	nochpoll,	/* poll */
	ddi_prop_op,
	NULL,
	D_NEW | D_MP | D_DEVMAP
};

static struct dev_ops vmm_ops = {
	DEVO_REV,
	0,
	ddi_no_info,
	nulldev,	/* identify */
	nulldev,	/* probe */
	vmm_attach,
	vmm_detach,
	nodev,		/* reset */
	&vmm_cb_ops,
	(struct bus_ops *)NULL
};

static struct modldrv modldrv = {
	&mod_driverops,
	"vmm",
	&vmm_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int	error;

	mutex_init(&vmmdev_mtx, NULL, MUTEX_DRIVER, NULL);
	list_create(&vmmdev_list, sizeof (vmm_softc_t),
	    offsetof(vmm_softc_t, vmm_node));
	vmmdev_minors = id_space_create("vmm_minors", VMM_CTL_MINOR + 1,
	    MAXMIN32);

	error = ddi_soft_state_init(&vmm_statep, sizeof (vmm_softc_t), 0);
	if (error) {
		return (error);
	}

	error = mod_install(&modlinkage);
	if (error) {
		ddi_soft_state_fini(&vmm_statep);
	}

	return (error);
}

int
_fini(void)
{
	int	error;

	error = mod_remove(&modlinkage);
	if (error) {
		return (error);
	}
	ddi_soft_state_fini(&vmm_statep);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
