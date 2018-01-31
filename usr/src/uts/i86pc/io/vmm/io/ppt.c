/*-
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */
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
 * Copyright 2018 Joyent, Inc
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/pciio.h>
#include <sys/smp.h>
#include <sys/sysctl.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

#include <machine/vmm.h>
#include <machine/vmm_dev.h>

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/pci_cap.h>
#include <sys/ppt_dev.h>
#include <sys/mkdev.h>
#include <sys/id_space.h>

#include "vmm_lapic.h"
#include "vmm_ktr.h"

#include "iommu.h"
#include "ppt.h"

#define	MAX_MSIMSGS	32

/*
 * If the MSI-X table is located in the middle of a BAR then that MMIO
 * region gets split into two segments - one segment above the MSI-X table
 * and the other segment below the MSI-X table - with a hole in place of
 * the MSI-X table so accesses to it can be trapped and emulated.
 *
 * So, allocate a MMIO segment for each BAR register + 1 additional segment.
 */
#define	MAX_MMIOSEGS	((PCIR_MAX_BAR_0 + 1) + 1)

struct pptintr_arg {
	struct pptdev	*pptdev;
	uint64_t	addr;
	uint64_t	msg_data;
};

struct pptseg {
	vm_paddr_t	gpa;
	size_t		len;
	int		wired;
};

struct pptbar {
	uint64_t base;
	uint64_t size;
	uint_t type;
	ddi_acc_handle_t io_handle;
	caddr_t io_ptr;
};

struct pptdev {
	dev_info_t		*pptd_dip;
	list_node_t		pptd_node;
	ddi_acc_handle_t	pptd_cfg;
	dev_t			pptd_dev;
	struct pptbar		pptd_bars[PCI_BASE_NUM];
	struct vm		*vm;
	struct pptseg mmio[MAX_MMIOSEGS];
	struct {
		int	num_msgs;		/* guest state */
		boolean_t is_fixed;
		size_t	inth_sz;
		ddi_intr_handle_t *inth;
		struct pptintr_arg arg[MAX_MSIMSGS];
	} msi;

	struct {
		int num_msgs;
		size_t inth_sz;
		size_t arg_sz;
		ddi_intr_handle_t *inth;
		struct pptintr_arg *arg;
	} msix;
};


static void		*ppt_state;
static kmutex_t		pptdev_mtx;
static list_t		pptdev_list;
static id_space_t	*pptdev_minors = NULL;

static ddi_device_acc_attr_t ppt_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STORECACHING_OK_ACC,
	DDI_DEFAULT_ACC
};

static int
ppt_open(dev_t *devp, int flag, int otyp, cred_t *cr)
{
	/* XXX: require extra privs? */
	return (0);
}

#define	BAR_TO_IDX(bar)	(((bar) - PCI_CONF_BASE0) / PCI_BAR_SZ_32)
#define	BAR_VALID(b)	(			\
		(b) >= PCI_CONF_BASE0 &&	\
		(b) <= PCI_CONF_BASE5 &&	\
		((b) & (PCI_BAR_SZ_32-1)) == 0)

static int
ppt_ioctl(dev_t dev, int cmd, intptr_t arg, int md, cred_t *cr, int *rv)
{
	minor_t minor = getminor(dev);
	struct pptdev *ppt;
	void *data = (void *)arg;

	if ((ppt = ddi_get_soft_state(ppt_state, minor)) == NULL) {
		return (ENOENT);
	}

	switch (cmd) {
	case PPT_CFG_READ: {
		struct ppt_cfg_io cio;
		ddi_acc_handle_t cfg = ppt->pptd_cfg;

		if (ddi_copyin(data, &cio, sizeof (cio), md) != 0) {
			return (EFAULT);
		}
		switch (cio.pci_width) {
		case 4:
			cio.pci_data = pci_config_get32(cfg, cio.pci_off);
			break;
		case 2:
			cio.pci_data = pci_config_get16(cfg, cio.pci_off);
			break;
		case 1:
			cio.pci_data = pci_config_get8(cfg, cio.pci_off);
			break;
		default:
			return (EINVAL);
		}

		if (ddi_copyout(&cio, data, sizeof (cio), md) != 0) {
			return (EFAULT);
		}
		return (0);
	}
	case PPT_CFG_WRITE: {
		struct ppt_cfg_io cio;
		ddi_acc_handle_t cfg = ppt->pptd_cfg;

		if (ddi_copyin(data, &cio, sizeof (cio), md) != 0) {
			return (EFAULT);
		}
		switch (cio.pci_width) {
		case 4:
			pci_config_put32(cfg, cio.pci_off, cio.pci_data);
			break;
		case 2:
			pci_config_put16(cfg, cio.pci_off, cio.pci_data);
			break;
		case 1:
			pci_config_put8(cfg, cio.pci_off, cio.pci_data);
			break;
		default:
			return (EINVAL);
		}

		return (0);
	}
	case PPT_BAR_QUERY: {
		struct ppt_bar_query barg;
		struct pptbar *pbar;

		if (ddi_copyin(data, &barg, sizeof (barg), md) != 0) {
			return (EFAULT);
		}
		if (barg.pbq_baridx >= PCI_BASE_NUM) {
			return (EINVAL);
		}
		pbar = &ppt->pptd_bars[barg.pbq_baridx];

		if (pbar->base == 0 || pbar->size == 0) {
			return (ENOENT);
		}
		barg.pbq_type = pbar->type;
		barg.pbq_base = pbar->base;
		barg.pbq_size = pbar->size;

		if (ddi_copyout(&barg, data, sizeof (barg), md) != 0) {
			return (EFAULT);
		}
		return (0);
	}
	case PPT_BAR_READ: {
		struct ppt_bar_io bio;
		struct pptbar *pbar;
		void *addr;
		uint_t rnum;
		ddi_acc_handle_t cfg;

		if (ddi_copyin(data, &bio, sizeof (bio), md) != 0) {
			return (EFAULT);
		}
		rnum = bio.pbi_bar;
		if (rnum >= PCI_BASE_NUM) {
			return (EINVAL);
		}
		pbar = &ppt->pptd_bars[rnum];
		if (pbar->type != PCI_ADDR_IO || pbar->io_handle == NULL) {
			return (EINVAL);
		}
		addr = pbar->io_ptr + bio.pbi_off;

		switch (bio.pbi_width) {
		case 4:
			bio.pbi_data = ddi_get32(pbar->io_handle, addr);
			break;
		case 2:
			bio.pbi_data = ddi_get16(pbar->io_handle, addr);
			break;
		case 1:
			bio.pbi_data = ddi_get8(pbar->io_handle, addr);
			break;
		default:
			return (EINVAL);
		}

		if (ddi_copyout(&bio, data, sizeof (bio), md) != 0) {
			return (EFAULT);
		}
		return (0);
	}
	case PPT_BAR_WRITE: {
		struct ppt_bar_io bio;
		struct pptbar *pbar;
		void *addr;
		uint_t rnum;
		ddi_acc_handle_t cfg;

		if (ddi_copyin(data, &bio, sizeof (bio), md) != 0) {
			return (EFAULT);
		}
		rnum = bio.pbi_bar;
		if (rnum >= PCI_BASE_NUM) {
			return (EINVAL);
		}
		pbar = &ppt->pptd_bars[rnum];
		if (pbar->type != PCI_ADDR_IO || pbar->io_handle == NULL) {
			return (EINVAL);
		}
		addr = pbar->io_ptr + bio.pbi_off;

		switch (bio.pbi_width) {
		case 4:
			ddi_put32(pbar->io_handle, addr, bio.pbi_data);
			break;
		case 2:
			ddi_put16(pbar->io_handle, addr, bio.pbi_data);
			break;
		case 1:
			ddi_put8(pbar->io_handle, addr, bio.pbi_data);
			break;
		default:
			return (EINVAL);
		}

		return (0);
	}

	default:
		return (ENOTTY);
	}

	return (0);
}


static void
ppt_bar_wipe(struct pptdev *ppt)
{
	uint_t i;

	for (i = 0; i < PCI_BASE_NUM; i++) {
		struct pptbar *pbar = &ppt->pptd_bars[i];
		if (pbar->type == PCI_ADDR_IO) {
			ddi_regs_map_free(&pbar->io_handle);
		}
	}
	bzero(&ppt->pptd_bars, sizeof (ppt->pptd_bars));
}

static int
ppt_bar_crawl(struct pptdev *ppt)
{
	pci_regspec_t *regs;
	uint_t rcount, i;
	int err = 0, rlen;

	if (ddi_getlongprop(DDI_DEV_T_ANY, ppt->pptd_dip, DDI_PROP_DONTPASS,
	    "assigned-addresses", (caddr_t)&regs, &rlen) != DDI_PROP_SUCCESS) {
		return (EIO);
	}

	VERIFY3S(rlen, >, 0);
	rcount = (rlen * sizeof (int)) / sizeof (pci_regspec_t);
	for (i = 0; i < rcount; i++) {
		pci_regspec_t *reg = &regs[i];
		struct pptbar *pbar;
		uint_t bar, rnum;

		DTRACE_PROBE1(ppt__crawl__reg, pci_regspec_t *, reg);
		bar = PCI_REG_REG_G(reg->pci_phys_hi);
		if (!BAR_VALID(bar)) {
			continue;
		}

		rnum = BAR_TO_IDX(bar);
		pbar = &ppt->pptd_bars[rnum];
		/* is this somehow already populated? */
		if (pbar->base != 0 || pbar->size != 0) {
			err = EEXIST;
			break;
		}

		pbar->type = reg->pci_phys_hi & PCI_ADDR_MASK;
		pbar->base = ((uint64_t)reg->pci_phys_mid << 32) |
		    (uint64_t)reg->pci_phys_low;
		pbar->size = ((uint64_t)reg->pci_size_hi << 32) |
		    (uint64_t)reg->pci_size_low;
		if (pbar->type == PCI_ADDR_IO) {
			err = ddi_regs_map_setup(ppt->pptd_dip, rnum,
			    &pbar->io_ptr, 0, 0, &ppt_attr, &pbar->io_handle);
			if (err != 0) {
				break;
			}
		}
	}
	kmem_free(regs, rlen);

	if (err != 0) {
		ppt_bar_wipe(ppt);
	}
	return (err);
}

static int
ppt_ddi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct pptdev *ppt = NULL;
	char name[PPT_MAXNAMELEN];
	minor_t minor;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	minor = id_alloc_nosleep(pptdev_minors);
	if (minor == -1) {
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(ppt_state, minor) != DDI_SUCCESS) {
		goto fail;
	}
	VERIFY(ppt = ddi_get_soft_state(ppt_state, minor));
	ppt->pptd_dip = dip;
	ddi_set_driver_private(dip, ppt);

	if (pci_config_setup(dip, &ppt->pptd_cfg) != DDI_SUCCESS) {
		goto fail;
	}
	if (ppt_bar_crawl(ppt) != 0) {
		goto fail;
	}

	if (snprintf(name, sizeof (name), "ppt%u", minor)
	    >= PPT_MAXNAMELEN - 1) {
		goto fail;
	}
	if (ddi_create_minor_node(dip, name, S_IFCHR, minor,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		goto fail;
	}

	ppt->pptd_dev = makedevice(ddi_driver_major(dip), minor);
	mutex_enter(&pptdev_mtx);
	list_insert_tail(&pptdev_list, ppt);
	mutex_exit(&pptdev_mtx);

	return (DDI_SUCCESS);

fail:
	if (ppt != NULL) {
		ddi_remove_minor_node(dip, NULL);
		if (ppt->pptd_cfg != NULL) {
			pci_config_teardown(&ppt->pptd_cfg);
		}
		ppt_bar_wipe(ppt);
		ddi_soft_state_free(ppt_state, minor);
	}
	id_free(pptdev_minors, minor);
	return (DDI_FAILURE);
}

static int
ppt_ddi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct pptdev *ppt;
	minor_t minor;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ppt = ddi_get_driver_private(dip);
	minor = getminor(ppt->pptd_dev);

	ASSERT3P(ddi_get_soft_state(ppt_state, minor), ==, ppt);

	mutex_enter(&pptdev_mtx);
	if (ppt->vm != NULL) {
		mutex_exit(&pptdev_mtx);
		return (DDI_FAILURE);
	}
	list_remove(&pptdev_list, ppt);
	mutex_exit(&pptdev_mtx);

	ddi_remove_minor_node(dip, NULL);
	ppt_bar_wipe(ppt);
	pci_config_teardown(&ppt->pptd_cfg);
	ddi_set_driver_private(dip, NULL);
	ddi_soft_state_free(ppt_state, minor);
	id_free(pptdev_minors, minor);

	return (DDI_SUCCESS);
}

static struct cb_ops ppt_cb_ops = {
	ppt_open,
	nulldev,	/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	ppt_ioctl,
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,
	NULL,
	D_NEW | D_MP | D_DEVMAP
};

static struct dev_ops ppt_ops = {
	DEVO_REV,
	0,
	ddi_no_info,
	nulldev,	/* identify */
	nulldev,	/* probe */
	ppt_ddi_attach,
	ppt_ddi_detach,
	nodev,		/* reset */
	&ppt_cb_ops,
	(struct bus_ops *)NULL
};

static struct modldrv modldrv = {
	&mod_driverops,
	"ppt",
	&ppt_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int error;

	mutex_init(&pptdev_mtx, NULL, MUTEX_DRIVER, NULL);
	list_create(&pptdev_list, sizeof (struct pptdev),
	    offsetof(struct pptdev, pptd_node));
	pptdev_minors = id_space_create("ppt_minors", 0, MAXMIN32);

	error = ddi_soft_state_init(&ppt_state, sizeof (struct pptdev), 0);
	if (error) {
		goto fail;
	}

	error = mod_install(&modlinkage);

fail:
	if (error) {
		ddi_soft_state_fini(&ppt_state);
		id_space_destroy(pptdev_minors);
		pptdev_minors = NULL;
	}
	return (error);
}

int
_fini(void)
{
	int error;

	error = mod_remove(&modlinkage);
	if (error)
		return (error);

	id_space_destroy(pptdev_minors);
	pptdev_minors = NULL;
	ddi_soft_state_fini(&ppt_state);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


static struct pptdev *
ppt_find(dev_t dev)
{
	struct pptdev *ppt;

	for (ppt = list_head(&pptdev_list); ppt != NULL;
	    ppt = list_next(&pptdev_list, ppt)) {
		if (ppt->pptd_dev == dev) {
			break;
		}
	}
	return (ppt);
}

static void
ppt_unmap_mmio(struct vm *vm, struct pptdev *ppt)
{
	int i;
	struct pptseg *seg;

	for (i = 0; i < MAX_MMIOSEGS; i++) {
		seg = &ppt->mmio[i];
		if (seg->len == 0)
			continue;
		(void)vm_unmap_mmio(vm, seg->gpa, seg->len);
		bzero(seg, sizeof(struct pptseg));
	}
}

static void
ppt_teardown_msi(struct pptdev *ppt)
{
	int i, rid;
#ifdef __FreeBSD__
	void *cookie;
	struct resource *res;
#endif
	int intr_cap = 0;

	if (ppt->msi.num_msgs == 0)
		return;

	for (i = 0; i < ppt->msi.num_msgs; i++) {
#ifdef __FreeBSD__
		rid = ppt->msi.startrid + i;
		res = ppt->msi.res[i];
		cookie = ppt->msi.cookie[i];

		if (cookie != NULL)
			bus_teardown_intr(ppt->dev, res, cookie);

		if (res != NULL)
			bus_release_resource(ppt->dev, SYS_RES_IRQ, rid, res);
		
		ppt->msi.res[i] = NULL;
		ppt->msi.cookie[i] = NULL;
#else
		(void) ddi_intr_get_cap(ppt->msi.inth[i], &intr_cap);
		if (intr_cap & DDI_INTR_FLAG_BLOCK)
			ddi_intr_block_disable(&ppt->msi.inth[i], 1);
		else
			ddi_intr_disable(ppt->msi.inth[i]);

		ddi_intr_remove_handler(ppt->msi.inth[i]);
		ddi_intr_free(ppt->msi.inth[i]);

		ppt->msi.inth[i] = NULL;
#endif
	}

#ifdef __FreeBSD__
	if (ppt->msi.startrid == 1)
		pci_release_msi(ppt->dev);
#else
	kmem_free(ppt->msi.inth, ppt->msi.inth_sz);
	ppt->msi.inth = NULL;
	ppt->msi.inth_sz = 0;
	ppt->msi.is_fixed = B_FALSE;
#endif

	ppt->msi.num_msgs = 0;
}

static void
ppt_teardown_msix_intr(struct pptdev *ppt, int idx)
{
#ifdef __FreeBSD__
	int rid;
	struct resource *res;
	void *cookie;

	rid = ppt->msix.startrid + idx;
	res = ppt->msix.res[idx];
	cookie = ppt->msix.cookie[idx];

	if (cookie != NULL) 
		bus_teardown_intr(ppt->dev, res, cookie);

	if (res != NULL) 
		bus_release_resource(ppt->dev, SYS_RES_IRQ, rid, res);

	ppt->msix.res[idx] = NULL;
	ppt->msix.cookie[idx] = NULL;
#else
	if (ppt->msix.inth != NULL && ppt->msix.inth[idx] != NULL) {
		int intr_cap;

		(void) ddi_intr_get_cap(ppt->msix.inth[idx], &intr_cap);
		if (intr_cap & DDI_INTR_FLAG_BLOCK)
			ddi_intr_block_disable(&ppt->msix.inth[idx], 1);
		else
			ddi_intr_disable(ppt->msix.inth[idx]);

		ddi_intr_remove_handler(ppt->msix.inth[idx]);
	}
#endif
}

static void
ppt_teardown_msix(struct pptdev *ppt)
{
	uint_t i;

	if (ppt->msix.num_msgs == 0)
		return;

	for (i = 0; i < ppt->msix.num_msgs; i++)
		ppt_teardown_msix_intr(ppt, i);

	if (ppt->msix.inth) {
		for (i = 0; i < ppt->msix.num_msgs; i++)
			ddi_intr_free(ppt->msix.inth[i]);
		kmem_free(ppt->msix.inth, ppt->msix.inth_sz);
		ppt->msix.inth = NULL;
		ppt->msix.inth_sz = 0;
		kmem_free(ppt->msix.arg, ppt->msix.arg_sz);
		ppt->msix.arg = NULL;
		ppt->msix.arg_sz = 0;
	}

	ppt->msix.num_msgs = 0;
}

int
ppt_assigned_devices(struct vm *vm)
{
	struct pptdev *ppt;
	uint_t num = 0;

	mutex_enter(&pptdev_mtx);
	for (ppt = list_head(&pptdev_list); ppt != NULL;
	    ppt = list_next(&pptdev_list, ppt)) {
		if (ppt->vm == vm) {
			num++;
		}
	}
	mutex_exit(&pptdev_mtx);
	return (num);
}

boolean_t
ppt_is_mmio(struct vm *vm, vm_paddr_t gpa)
{
	struct pptdev *ppt = list_head(&pptdev_list);

	/* XXX: this should probably be restructured to avoid the lock */
	mutex_enter(&pptdev_mtx);
	for (ppt = list_head(&pptdev_list); ppt != NULL;
	    ppt = list_next(&pptdev_list, ppt)) {
		if (ppt->vm != vm) {
			continue;
		}

		for (uint_t i = 0; i < MAX_MMIOSEGS; i++) {
			struct pptseg *seg = &ppt->mmio[i];

			if (seg->len == 0)
				continue;
			if (gpa >= seg->gpa && gpa < seg->gpa + seg->len) {
				mutex_exit(&pptdev_mtx);
				return (B_TRUE);
			}
		}
	}

	mutex_exit(&pptdev_mtx);
	return (B_FALSE);
}

int
ppt_assign_device(struct vm *vm, dev_t dev)
{
	struct pptdev *ppt;

	mutex_enter(&pptdev_mtx);
	ppt = ppt_find(dev);
	if (ppt == NULL) {
		mutex_exit(&pptdev_mtx);
		return (ENOENT);
	}

	/* Only one VM may own a device at any given time */
	if (ppt->vm != NULL && ppt->vm != vm) {
		mutex_exit(&pptdev_mtx);
		return (EBUSY);
	}

	if (pci_save_config_regs(ppt->pptd_dip) != DDI_SUCCESS) {
		return (EIO);
	}
	pcie_flr(ppt->pptd_dip,
	    MAX(pcie_get_max_completion_timeout(ppt->pptd_dip) / 1000, 10),
	    B_TRUE);

	/*
	 * Restore the device state after reset and then perform another save
	 * so the "pristine" state can be restored when the device is removed
	 * from the guest.
	 */
	if (pci_restore_config_regs(ppt->pptd_dip) != DDI_SUCCESS ||
	    pci_save_config_regs(ppt->pptd_dip) != DDI_SUCCESS) {
		return (EIO);
	}

	ppt->vm = vm;
	iommu_remove_device(iommu_host_domain(), pci_get_bdf(ppt->pptd_dip));
	iommu_add_device(vm_iommu_domain(vm), pci_get_bdf(ppt->pptd_dip));

	mutex_exit(&pptdev_mtx);
	return (0);
}

static void
ppt_reset_pci_power_state(dev_info_t *dip)
{
	ddi_acc_handle_t cfg;
	uint16_t cap_ptr, val;

	if (pci_config_setup(dip, &cfg) != DDI_SUCCESS)
		return;

	if (PCI_CAP_LOCATE(cfg, PCI_CAP_ID_PM, &cap_ptr) != DDI_SUCCESS)
		return;

	val = PCI_CAP_GET16(cfg, NULL, cap_ptr, PCI_PMCSR);
	if ((val & PCI_PMCSR_STATE_MASK) != PCI_PMCSR_D0) {
		val = (val & ~PCI_PMCSR_STATE_MASK) | PCI_PMCSR_D0;
		(void) PCI_CAP_PUT16(cfg, NULL, cap_ptr, PCI_PMCSR, val);
	}
}

static void
ppt_do_unassign(struct pptdev *ppt)
{
	struct vm *vm = ppt->vm;

	ASSERT3P(vm, !=, NULL);
	ASSERT(MUTEX_HELD(&pptdev_mtx));


	pcie_flr(ppt->pptd_dip,
	    MAX(pcie_get_max_completion_timeout(ppt->pptd_dip) / 1000, 10),
	    B_TRUE);

	/*
	 * Restore from the state saved during device assignment.
	 * If the device power state has been altered, that must be remedied
	 * first, as it will reset register state during the transition.
	 */
	ppt_reset_pci_power_state(ppt->pptd_dip);
	(void) pci_restore_config_regs(ppt->pptd_dip);

	ppt_unmap_mmio(vm, ppt);
	ppt_teardown_msi(ppt);
	ppt_teardown_msix(ppt);
	iommu_remove_device(vm_iommu_domain(vm), pci_get_bdf(ppt->pptd_dip));
	iommu_add_device(iommu_host_domain(), pci_get_bdf(ppt->pptd_dip));
	ppt->vm = NULL;
}

int
ppt_unassign_device(struct vm *vm, dev_t dev)
{
	struct pptdev *ppt;

	mutex_enter(&pptdev_mtx);
	ppt = ppt_find(dev);
	if (ppt == NULL) {
		mutex_exit(&pptdev_mtx);
		return (ENOENT);
	}

	/* If this device is not owned by this 'vm' then bail out. */
	if (ppt->vm != vm) {
		mutex_exit(&pptdev_mtx);
		return (EBUSY);
	}

	ppt_do_unassign(ppt);
	mutex_exit(&pptdev_mtx);
	return (0);
}

int
ppt_unassign_all(struct vm *vm)
{
	struct pptdev *ppt;

	mutex_enter(&pptdev_mtx);
	for (ppt = list_head(&pptdev_list); ppt != NULL;
	    ppt = list_next(&pptdev_list, ppt)) {
		if (ppt->vm == vm) {
			ppt_do_unassign(ppt);
		}
	}
	mutex_exit(&pptdev_mtx);

	return (0);
}

int
ppt_map_mmio(struct vm *vm, dev_t dev, vm_paddr_t gpa, size_t len,
    vm_paddr_t hpa)
{
	struct pptdev *ppt;

	mutex_enter(&pptdev_mtx);
	ppt = ppt_find(dev);
	if (ppt == NULL) {
		mutex_exit(&pptdev_mtx);
		return (ENOENT);
	}
	if (ppt->vm != vm) {
		mutex_exit(&pptdev_mtx);
		return (EBUSY);
	}

	for (uint_t i = 0; i < MAX_MMIOSEGS; i++) {
		struct pptseg *seg = &ppt->mmio[i];

		if (seg->len == 0) {
			int error;

			error = vm_map_mmio(vm, gpa, len, hpa);
			if (error == 0) {
				seg->gpa = gpa;
				seg->len = len;
			}
			mutex_exit(&pptdev_mtx);
			return (error);
		}
	}
	mutex_exit(&pptdev_mtx);
	return (ENOSPC);
}

static uint_t
pptintr(caddr_t arg, caddr_t unused)
{
	struct pptintr_arg *pptarg = (struct pptintr_arg *)arg;
	struct pptdev *ppt = pptarg->pptdev;

	if (ppt->vm != NULL) {
		lapic_intr_msi(ppt->vm, pptarg->addr, pptarg->msg_data);
	} else {
		/*
		 * XXX
		 * This is not expected to happen - panic?
		 */
	}

	/*
	 * For legacy interrupts give other filters a chance in case
	 * the interrupt was not generated by the passthrough device.
	 */
	return (ppt->msi.is_fixed ? DDI_INTR_UNCLAIMED : DDI_INTR_CLAIMED);
}

int
ppt_setup_msi(struct vm *vm, int vcpu, dev_t dev, uint64_t addr, uint64_t msg,
    int numvec)
{
	int i, rid, flags;
	int msi_count, startrid, error, tmp;
	int intr_type, intr_cap = 0;
	struct pptdev *ppt;

	if (numvec < 0 || numvec > MAX_MSIMSGS)
		return (EINVAL);

	ppt = ppt_find(dev);
	if (ppt == NULL)
		return (ENOENT);
	if (ppt->vm != vm)		/* Make sure we own this device */
		return (EBUSY);

	/* Free any allocated resources */
	ppt_teardown_msi(ppt);

	if (numvec == 0)		/* nothing more to do */
		return (0);

	if (ddi_intr_get_navail(ppt->pptd_dip, DDI_INTR_TYPE_MSI,
	    &msi_count) != DDI_SUCCESS) {
		if (ddi_intr_get_navail(ppt->pptd_dip, DDI_INTR_TYPE_FIXED,
		    &msi_count) != DDI_SUCCESS)
			return (EINVAL);

		intr_type = DDI_INTR_TYPE_FIXED;
		ppt->msi.is_fixed = B_TRUE;
	} else {
		intr_type = DDI_INTR_TYPE_MSI;
	}

	/*
	 * The device must be capable of supporting the number of vectors
	 * the guest wants to allocate.
	 */
	if (numvec > msi_count)
		return (EINVAL);

	ppt->msi.inth_sz = numvec * sizeof (ddi_intr_handle_t);
	ppt->msi.inth = kmem_zalloc(ppt->msi.inth_sz, KM_SLEEP);
	if (ddi_intr_alloc(ppt->pptd_dip, ppt->msi.inth, intr_type, 0,
	    numvec, &msi_count, 0) != DDI_SUCCESS) {
		kmem_free(ppt->msi.inth, ppt->msi.inth_sz);
		return (EINVAL);
	}

	/*
	 * Again, make sure we actually got as many vectors as the guest wanted
	 * to allocate.
	 */
	if (numvec != msi_count) {
		ppt_teardown_msi(ppt);
		return (EINVAL);
	}
	/*
	 * Set up & enable interrupt handler for each vector.
	 */
	for (i = 0; i < numvec; i++) {
		ppt->msi.num_msgs = i + 1;
		ppt->msi.arg[i].pptdev = ppt;
		ppt->msi.arg[i].addr = addr;
		ppt->msi.arg[i].msg_data = msg + i;

		if (ddi_intr_add_handler(ppt->msi.inth[i], pptintr,
		    &ppt->msi.arg[i], NULL) != DDI_SUCCESS)
			break;

		(void) ddi_intr_get_cap(ppt->msi.inth[i], &intr_cap);
		if (intr_cap & DDI_INTR_FLAG_BLOCK)
			error = ddi_intr_block_enable(&ppt->msi.inth[i], 1);
		else
			error = ddi_intr_enable(ppt->msi.inth[i]);

		if (error != DDI_SUCCESS)
			break;
	}

	if (i < numvec) {
		ppt_teardown_msi(ppt);
		return (ENXIO);
	}

	return (0);
}

int
ppt_setup_msix(struct vm *vm, int vcpu, dev_t dev, int idx, uint64_t addr,
    uint64_t msg, uint32_t vector_control)
{
	struct pptdev *ppt;
	struct pci_devinfo *dinfo;
	int numvec, alloced, rid, error;
	size_t res_size, cookie_size, arg_size;
	int intr_cap;

	ppt = ppt_find(dev);
	if (ppt == NULL)
		return (ENOENT);
	if (ppt->vm != vm)		/* Make sure we own this device */
		return (EBUSY);

	/*
	 * First-time configuration:
	 * 	Allocate the MSI-X table
	 *	Allocate the IRQ resources
	 *	Set up some variables in ppt->msix
	 */
	if (ppt->msix.num_msgs == 0) {
		dev_info_t *dip = ppt->pptd_dip;

		if (ddi_intr_get_navail(dip, DDI_INTR_TYPE_MSIX,
		    &numvec) != DDI_SUCCESS)
			return (EINVAL);

		ppt->msix.num_msgs = numvec;

		ppt->msix.arg_sz = numvec * sizeof(ppt->msix.arg[0]);
		ppt->msix.arg = kmem_zalloc(ppt->msix.arg_sz, KM_SLEEP);
		ppt->msix.inth_sz = numvec * sizeof(ddi_intr_handle_t);
		ppt->msix.inth = kmem_zalloc(ppt->msix.inth_sz, KM_SLEEP);

		if (ddi_intr_alloc(dip, ppt->msix.inth, DDI_INTR_TYPE_MSIX, 0,
		    numvec, &alloced, 0) != DDI_SUCCESS) {
			kmem_free(ppt->msix.arg, ppt->msix.arg_sz);
			kmem_free(ppt->msix.inth, ppt->msix.inth_sz);
			ppt->msix.arg = NULL;
			ppt->msix.inth = NULL;
			ppt->msix.arg_sz = ppt->msix.inth_sz = 0;
			return (EINVAL);
		}

		if (numvec != alloced) {
			ppt_teardown_msix(ppt);
			return (EINVAL);
		}
	}

	if (idx >= ppt->msix.num_msgs)
		return (EINVAL);

	if ((vector_control & PCIM_MSIX_VCTRL_MASK) == 0) {
		/* Tear down the IRQ if it's already set up */
		ppt_teardown_msix_intr(ppt, idx);

		ppt->msix.arg[idx].pptdev = ppt;
		ppt->msix.arg[idx].addr = addr;
		ppt->msix.arg[idx].msg_data = msg;

		/* Setup the MSI-X interrupt */
		if (ddi_intr_add_handler(ppt->msix.inth[idx], pptintr,
		    &ppt->msix.arg[idx], NULL) != DDI_SUCCESS)
			return (ENXIO);

		(void) ddi_intr_get_cap(ppt->msix.inth[idx], &intr_cap);
		if (intr_cap & DDI_INTR_FLAG_BLOCK)
			error = ddi_intr_block_enable(&ppt->msix.inth[idx], 1);
		else
			error = ddi_intr_enable(ppt->msix.inth[idx]);

		if (error != DDI_SUCCESS) {
			ddi_intr_remove_handler(ppt->msix.inth[idx]);
			return (ENXIO);
		}
	} else {
		/* Masked, tear it down if it's already been set up */
		ppt_teardown_msix_intr(ppt, idx);
	}

	return (0);
}

int
ppt_get_limits(struct vm *vm, dev_t dev, int *msilimit, int *msixlimit)
{
	struct pptdev *ppt;

	mutex_enter(&pptdev_mtx);
	ppt = ppt_find(dev);
	if (ppt == NULL) {
		mutex_exit(&pptdev_mtx);
		return (ENOENT);
	}
	if (ppt->vm != vm) {
		mutex_exit(&pptdev_mtx);
		return (EBUSY);
	}

	if (ddi_intr_get_navail(ppt->pptd_dip, DDI_INTR_TYPE_MSI,
	    msilimit) != DDI_SUCCESS) {
		*msilimit = -1;
	}
	if (ddi_intr_get_navail(ppt->pptd_dip, DDI_INTR_TYPE_MSIX,
	    msixlimit) != DDI_SUCCESS) {
		*msixlimit = -1;
	}

	mutex_exit(&pptdev_mtx);
	return (0);
}
