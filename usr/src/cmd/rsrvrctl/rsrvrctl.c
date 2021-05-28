/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2021 Oxide Computer Company
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

#include <sys/vmm_dev.h>

static const char *g_pname;

static int
usage(boolean_t is_err)
{
	fprintf(stderr,
	    "Usage: %s [-a add] [-r remove] [-q]\n"
	    "\t-a <SZ> add SZ MiB to the reservoir\n"
	    "\t-r <SZ> remove SZ MiB from the reservoir\n"
	    "\t-q query reservoir state\n", g_pname);
	return (is_err ? EXIT_FAILURE : EXIT_SUCCESS);
}

static size_t
parse_size(const char *arg)
{
	size_t res;

	errno = 0;
	res = strtoul(arg, NULL, 0);
	if (errno != 0) {
		perror("Invalid size");
		exit(usage(B_TRUE));
	}

	return (res * 1024 * 1024);
}

static void
do_add(int fd, const char *arg)
{
	int res;
	size_t sz = parse_size(arg);

	res = ioctl(fd, VMM_RESV_ADD, sz);
	if (res != 0) {
		perror("Could not add to reservoir");
	}
}

static void
do_remove(int fd, const char *arg)
{
	int res;
	size_t sz = parse_size(arg);

	res = ioctl(fd, VMM_RESV_REMOVE, sz);
	if (res != 0) {
		perror("Could not remove from reservoir");
	}
}

static void
do_query(int fd)
{
	struct vmm_resv_query data;
	int res;

	res = ioctl(fd, VMM_RESV_QUERY, &data);
	if (res == -1) {
		perror("Could not query reservoir info");
		return;
	}

	printf("Free KiB:\t%llu\n"
	    "Allocated KiB:\t%llu\n"
	    "Transient Allocated KiB:\t%llu\n"
	    "Size limit KiB:\t%llu\n",
	    data.vrq_free_sz / 1024,
	    data.vrq_alloc_sz / 1024,
	    data.vrq_alloc_transient_sz / 1024,
	    data.vrq_limit / 1024);
}

int
main(int argc, char *argv[])
{
	char c;
	const char *opt_a = NULL, *opt_r = NULL;
	boolean_t opt_q = B_FALSE;
	int fd;

	g_pname = argv[0];

	for (optind = 1; (c = getopt(argc, argv, "a:r:qh")) != EOF; ) {
		switch (c) {
		case 'a':
			opt_a = optarg;
			break;
		case 'r':
			opt_r = optarg;
			break;
		case 'q':
			opt_q = B_TRUE;
			break;
		case 'h':
			return (usage(B_FALSE));
		default:
			return (usage(B_TRUE));
		}
	}
	if (optind < argc ||
	    (opt_a == NULL && opt_r == NULL && !opt_q) ||
	    (opt_a != NULL && opt_r != NULL)) {
		return (usage(B_TRUE));
	}

	fd = open(VMM_CTL_DEV, O_EXCL | O_RDWR);
	if (fd < 0) {
		perror("Could not open vmmctl");
		return (usage(B_TRUE));
	}

	if (opt_a != NULL) {
		do_add(fd, opt_a);
	}
	if (opt_r != NULL) {
		do_remove(fd, opt_r);
	}
	if (opt_q) {
		do_query(fd);
	}

	(void) close(fd);
	return (0);
}
