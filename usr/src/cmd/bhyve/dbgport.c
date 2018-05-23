/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/uio.h>
#include <sys/stat.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "inout.h"
#include "dbgport.h"
#include "pci_lpc.h"

#define	BVM_DBG_PORT	0x224
#define	BVM_DBG_SIG	('B' << 8 | 'V')

static struct dbgport_config_s {
	uint_t	dc_legacy_port;
	uint_t	dc_file_iobase;
	char	*dc_file_path;
} dbgport_config;

/* legacy state */
static int listen_fd, conn_fd;

/* file-debug state */
static int dbgport_file_fd;


static int
dbgport_legacy_handler(struct vmctx *ctx, int vcpu, int in, int port,
    int bytes, uint32_t *eax, void *arg)
{
	int nwritten, nread, printonce;
	int on = 1;
	char ch;

	if (bytes == 2 && in) {
		*eax = BVM_DBG_SIG;
		return (0);
	}

	if (bytes != 4)
		return (-1);

again:
	printonce = 0;
	while (conn_fd < 0) {
		if (!printonce) {
			printf("Waiting for connection from gdb\r\n");
			printonce = 1;
		}
		conn_fd = accept4(listen_fd, NULL, NULL, SOCK_NONBLOCK);
		if (conn_fd >= 0) {
			/* Avoid EPIPE after the client drops off. */
			(void)setsockopt(conn_fd, SOL_SOCKET, SO_NOSIGPIPE,
			    &on, sizeof(on));
			/* Improve latency for one byte at a time tranfers. */
			(void)setsockopt(conn_fd, IPPROTO_TCP, TCP_NODELAY,
			    &on, sizeof(on));
		} else if (errno != EINTR) {
			perror("accept");
		}
	}

	if (in) {
		nread = read(conn_fd, &ch, 1);
		if (nread == -1 && errno == EAGAIN)
			*eax = -1;
		else if (nread == 1)
			*eax = ch;
		else {
			close(conn_fd);
			conn_fd = -1;
			goto again;
		}
	} else {
		ch = *eax;
		nwritten = write(conn_fd, &ch, 1);
		if (nwritten != 1) {
			close(conn_fd);
			conn_fd = -1;
			goto again;
		}
	}
	return (0);
}

static int
dbgport_file_handler(struct vmctx *ctx, int vcpu, int in, int port, int bytes,
    uint32_t *eax, void *arg)
{
	int res;

	if (in != 0 || dbgport_file_fd == -1) {
		*eax = 0;
		return (0);
	}

	res = write(dbgport_file_fd, (char *)eax, bytes);
	if (res == -1) {
		fprintf(stderr, "dbgport: write error of %d (%s), closing\n",
		    dbgport_file_fd, strerror(errno));
		(void) close(dbgport_file_fd);
		dbgport_file_fd = -1;
	}
	return (0);
}

SYSRES_IO(BVM_DBG_PORT, 4);

int
dbgport_parse(char *opts)
{
	char *tok, *savp;

	if (dbgport_config.dc_legacy_port != 0 ||
	    dbgport_config.dc_file_path != NULL) {
		fprintf(stderr, "dbgport: multiple configs not allowed\n");
		return (EINVAL);
	}

	/* Is it the older TCP-port-only config? */
	if (strchr(opts, '=') == NULL) {
		int port;

		errno = 0;
		port = atoi(opts);
		if (port == 0 && errno != 0) {
			return (errno);
		}
		if (port < 1 || port < 65535) {
			return (EINVAL);
		}

		dbgport_config.dc_legacy_port = port;
		return (0);
	}

	/* Parse qemu-style file output options */
	tok = strtok_r(opts, ",", &savp);
	for (;tok != NULL; tok = strtok_r(NULL, ",", &savp)) {
		char *key = tok, *val;

		val = strchr(tok, '=');
		if (val == NULL) {
			fprintf(stderr, "dbport: key=value expected\n");
			return (EINVAL);
		}
		*val = '\0';
		val++;
		if (strcmp(key, "path") == 0) {
			dbgport_config.dc_file_path = val;
		} else if (strcmp(key, "iobase") == 0) {
			int ioport, res = 0;

			errno = 0;
			ioport = atoi(val);
			if (ioport == 0 && errno != 0) {
				res = errno;
			} else if (ioport < 1 || ioport > 65535) {
				res = EINVAL;
			}
			if (res != 0) {
				fprintf(stderr,
				    "dbgport: error parsing iobase\n");
				return (res);
			}
			dbgport_config.dc_file_iobase = ioport;
		} else {
			fprintf(stderr, "dbgport: unrecognized option %s\n",
			    key);
		}
	}
	if (dbgport_config.dc_file_path == NULL) {
		fprintf(stderr, "dbgport: path required\n");
		return (EINVAL);
	} else if (dbgport_config.dc_file_iobase == 0) {
		fprintf(stderr, "dbgport: iobase required\n");
		return (EINVAL);
	}
	dbgport_file_fd = open(dbgport_config.dc_file_path,
	    O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
	if (dbgport_file_fd == -1) {
		int err = errno;

		fprintf(stderr, "dbgport: open error %s\n", strerror(err));
		return (err);
	}

	return (0);
}

static void
dbgport_legacy_init(int sport)
{
	int reuse;
	struct sockaddr_in sin;
	struct inout_port dbgport = {
		"bvmdbg",
		BVM_DBG_PORT,
		1,
		IOPORT_F_INOUT,
		dbgport_legacy_handler
	};

	conn_fd = -1;

	if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(sport);

	reuse = 1;
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse,
	    sizeof(reuse)) < 0) {
		perror("setsockopt");
		exit(1);
	}

	if (bind(listen_fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("bind");
		exit(1);
	}

	if (listen(listen_fd, 1) < 0) {
		perror("listen");
		exit(1);
	}

	register_inout(&dbgport);
}

static void
dbgport_file_init()
{
	struct inout_port dbgport = {
		"dbgport",
		dbgport_config.dc_file_iobase,
		1,
		IOPORT_F_INOUT,
		dbgport_file_handler
	};

	register_inout(&dbgport);
}

void
dbgport_init()
{
	if (dbgport_config.dc_legacy_port != 0) {
		dbgport_legacy_init(dbgport_config.dc_legacy_port);
	} else if (dbgport_config.dc_file_path != NULL) {
		dbgport_file_init();
	}
}
