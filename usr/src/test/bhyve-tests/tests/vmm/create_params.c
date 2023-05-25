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
 * Copyright 2022 Oxide Computer Company
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/stat.h>
#include <errno.h>
#include <err.h>
#include <assert.h>
#include <sys/sysmacros.h>
#include <stdbool.h>
#include <libnvpair.h>

#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <vmmapi.h>

#include "common.h"

#define	ERR_BUF_SZ	4096

static int
attempt_create(int ctlfd, nvlist_t *params, nvlist_t **errs)
{
	size_t psize = 0;
	char *ppack = fnvlist_pack(params, &psize);
	char *err_buf = malloc(ERR_BUF_SZ);
	struct vm_create_nv nva = {
		.vcn_sz_param = psize,
		.vcn_param = ppack,
		.vcn_sz_error = ERR_BUF_SZ,
		.vcn_error = err_buf,
	};

	if (ioctl(ctlfd, VMM_CREATE_NV, &nva) != 0) {
		const int err = errno;

		fnvlist_pack_free(ppack, psize);
		if (nva.vcn_sz_error_valid != 0) {
			*errs = fnvlist_unpack(err_buf, nva.vcn_sz_error_valid);
		} else if (nva.vcn_sz_error != 0) {
			errx(EXIT_FAILURE,
			    "VMM_CREAT_NV failed, but error(s) not copied out");
		} else {
			/* Some other unrelated error, so emit empty nvlist */
			*errs = fnvlist_alloc();
		}
		return (err);
	} else {
		*errs = NULL;
		fnvlist_pack_free(ppack, psize);
		return (0);
	}
}

/*
 * Manually attempt a bad create without an error buffer to check that the error
 * size is still communicated out.
 */
static void
test_err_sizing(int ctlfd)
{
	nvlist_t *params = fnvlist_alloc();
	size_t psize = 0;
	char *packed = fnvlist_pack(params, &psize);
	struct vm_create_nv nva = {
		.vcn_param = packed,
		.vcn_error = NULL,
		.vcn_sz_param = psize,
		.vcn_sz_error = 0,
	};

	if (ioctl(ctlfd, VMM_CREATE_NV, &nva) == 0) {
		errx(EXIT_FAILURE, "VMM_CREAT_NV should fail on empty params");
	}
	if (nva.vcn_sz_error == 0) {
		/*
		 * Even without a buffer to place the errors in, we still expect
		 * the packed size to be communicated out.
		 */
		errx(EXIT_FAILURE, "VMM_CREAT_NV did not communicate error sz");
	}
	fnvlist_pack_free(packed, psize);
	fnvlist_free(params);
}

/*
 * Test that a create request without proper 'name' parameter is rejected with
 * the expected errcode.
 */
static void
test_empty(int ctlfd)
{
	nvlist_t *params = fnvlist_alloc();

	/* Check that lack of the 'name' attribute results in expected error */
	nvlist_t *errors = NULL;
	if (attempt_create(ctlfd, params, &errors) == 0) {
		errx(EXIT_FAILURE, "VMM_CREAT_NV should fail on empty params");
	}
	nvlist_t *name_err = fnvlist_lookup_nvlist(errors, "name");
	if (fnvlist_lookup_uint32(name_err, "code") != VPE_MISSING_KEY) {
		errx(EXIT_FAILURE,
		    "lacking expected errcode for missing 'name'");
	}
	fnvlist_free(params);
}

/*
 * Try the most basic case of create a named VM
 */
static void
test_basic(int ctlfd, const char *name)
{
	nvlist_t *params = fnvlist_alloc();
	fnvlist_add_string(params, "name", name);

	nvlist_t *errors = NULL;
	if (attempt_create(ctlfd, params, &errors) != 0) {
		err(EXIT_FAILURE, "VMM_CREAT_NV failed");
	}
	assert(errors == NULL);
	fnvlist_free(params);
}

/*
 * Add on the parameter for memory reservoir usage.
 */
static void
test_reservoir(int ctlfd, const char *name)
{
	nvlist_t *params = fnvlist_alloc();
	fnvlist_add_string(params, "name", name);
	fnvlist_add_boolean_value(params, "vmm.use_reservoir", true);

	nvlist_t *errors = NULL;
	if (attempt_create(ctlfd, params, &errors) != 0) {
		err(EXIT_FAILURE, "VMM_CREAT_NV failed");
	}
	assert(errors == NULL);
	fnvlist_free(params);
}

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);
	char vm_name[VM_MAX_NAMELEN];

	name_test_vm(suite_name, vm_name);

	int ctlfd = open(VMM_CTL_DEV, O_EXCL | O_RDWR);
	if (ctlfd < 0) {
		err(EXIT_FAILURE, "could not open /dev/vmmctl");
	}

	struct vm_create_nv nva = { 0 };
	if (ioctl(ctlfd, VMM_CREATE_NV, nva) == 0) {
		errx(EXIT_FAILURE,
		    "VMM_CREAT_NV should fail on missing params");
	}

	test_err_sizing(ctlfd);

	test_empty(ctlfd);

	test_basic(ctlfd, vm_name);
	(void) destroy_instance(suite_name);

	test_reservoir(ctlfd, vm_name);
	(void) destroy_instance(suite_name);

	(void) close(ctlfd);
	(void) printf("%s\tPASS\n", suite_name);
	return (EXIT_SUCCESS);
}
