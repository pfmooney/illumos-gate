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
 * Copyright 2018 Joyent Inc.
 */

#include <devfsadm.h>
#include <strings.h>
#include <stdio.h>
#include <sys/dtrace.h>

static int devfs_viona_ln(di_minor_t minor, di_node_t node);

/*
 * The amount of documentation for this format is unsurprisingly limited. There
 * is probably a better match that we could do. This is modeled off of the
 * misc_link_i386.c things that we are matching. Like xsvc and its ilk we look
 * for most ddi_psuedo devices and look for node names that are kvm.
 */
static devfsadm_create_t devfs_viona_create_cbt[] = {
	{ "pseudo", "ddi_pseudo", NULL, TYPE_EXACT, ILEVEL_0, devfs_viona_ln }
};

DEVFSADM_CREATE_INIT_V0(devfs_viona_create_cbt);

static int
devfs_viona_ln(di_minor_t minor, di_node_t node)
{
	char *mn;

	if (strcmp(di_driver_name(node), "viona") != 0)
		return (DEVFSADM_CONTINUE);

	mn = di_minor_name(minor);
	if (mn == NULL)
		return (DEVFSADM_CONTINUE);

	(void) devfsadm_mklink(mn, node, minor, 0);
	return (DEVFSADM_CONTINUE);
}
