/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2019 John H. Baldwin <jhb@FreeBSD.org>
 * Copyright (c) 2019 Joyent, Inc.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <pthread.h>
#include <string.h>
#include <strings.h>
#include <err.h>
#include <stdlib.h>

#include <sys/avl.h>
#include <sys/debug.h>
#include <sys/param.h>
#include <sys/stddef.h>

#include "config.h"

static avl_tree_t config_tree;
/*
 * config_lock protects config_tree and its contents.  After a call to
 * finish_config(), it is expected that no items will be added/removed from
 * config_tree, although value expansion may still occur.
 */
pthread_mutex_t config_lock;
boolean_t config_finished;

#define	CONFIG_MAX_DEPTH	15

typedef enum {
	CF_EXPANDED	= (1 << 0),
	CF_NEEDS_EXPAND	= (1 << 1),
	CF_BOOL_CHECKED	= (1 << 2),
} config_flags_t;

typedef struct config_node {
	avl_node_t	cn_node;
	config_flags_t	cn_flags;
	boolean_t	cn_bool;
	const char	*cn_path;
	const char	*cn_value_raw;
	const char	*cn_value_expanded;
} config_node_t;

static const char *expand_config_value(config_node_t *, uint_t);
static config_node_t *find_config_path(const char *, avl_index_t *);

static int
config_node_compare(const void *a, const void *b)
{
	const config_node_t *left = a;
	const config_node_t *right = b;
	const int res = strcmp(left->cn_path, right->cn_path);

	if (res > 0) {
		return (1);
	} else if (res < 0) {
		return (-1);
	}
	return (0);
}

void
init_config(void)
{
	VERIFY0(pthread_mutex_init(&config_lock, NULL));
	avl_create(&config_tree, config_node_compare, sizeof (config_node_t),
	    offsetof(config_node_t, cn_node));
}

void
finish_config(void)
{
	pthread_mutex_lock(&config_lock);
	VERIFY(!config_finished);
	config_finished = B_TRUE;
	pthread_mutex_unlock(&config_lock);
}

static size_t
process_config_value(const char *orig, char *buf, size_t buflen, uint_t depth)
{
	const char *vp;
	size_t len = 0;

	for (vp = orig; *vp != '\0'; vp++) {
		config_node_t *cn = NULL;

		if (*vp != '%') {
			if (buf != NULL && buflen > 0) {
				*buf = *vp;
				buf++;
				buflen--;
			}
			continue;
		}
		vp++;
		if (*vp == '%') {
			/* Escaped '%' */
			len--;
			continue;
		}

		/* reference to another value */
		if (*vp == '(') {
			const char *end;
			size_t namelen;
			char *namebuf = NULL;

			vp++;
			end = strchr(vp, ')');
			if (end == NULL) {
				warnx("Unclosed reference in \"%s\"", orig);
				break;
			}
			namelen = (uintptr_t)end - (uintptr_t)vp + 1;
			namebuf = malloc(namelen);
			if (namebuf == NULL) {
				errx(4, "Failed to allocate memory");
			}
			strlcpy(namebuf, vp, namelen);
			cn = find_config_path(namebuf, NULL);
			free(namebuf);
			/* subtract length for name and %() delimiters */
			len -= namelen + 2;
		} else {
			size_t namelen;

			namelen = strlen(vp);
			/* use the rest of the value as the key */
			cn = find_config_path(vp, NULL);
			/* subtract length for name and % delimiter */
			len -= namelen + 1;
		}

		if (cn != NULL) {
			size_t reflen;
			const char *ref;

			ref = expand_config_value(cn, depth + 1);
			reflen = strlen(ref);
			len += reflen;
			if (buf != NULL && buflen >= reflen) {
				(void) strncpy(buf, ref, reflen);
				buf += reflen;
				buflen -= reflen;
			}
		}
	}

	/* account for NUL terminator */
	len++;
	if (buf != NULL && buflen != 0) {
		*buf = '\0';
	}
	return (len);
}

static const char *
expand_config_value(config_node_t *cn, uint_t depth)
{
	const char *result = NULL;
	char *buf;
	size_t len, done_len;

	if ((cn->cn_flags & CF_NEEDS_EXPAND) == 0) {
		return (cn->cn_value_raw);
	} else if ((cn->cn_flags & CF_EXPANDED) != 0) {
		if (cn->cn_value_expanded != NULL) {
			return (cn->cn_value_expanded);
		} else {
			return ("");
		}
	}

	if (depth >= CONFIG_MAX_DEPTH) {
		warnx("Exceeded max reference depth");
		return ("");
	}

	if (depth == 0) {
		pthread_mutex_lock(&config_lock);
	} else {
		ASSERT(pthread_mutex_isowned_np(&config_lock));
	}

	/*
	 * Double check that the value was not expanded while waiting to
	 * acquire the config_lock.
	 */
	if ((cn->cn_flags & CF_EXPANDED) != 0) {
		result = cn->cn_value_expanded;
		goto done;
	}

	len = process_config_value(cn->cn_value_raw, NULL, 0, depth);
	if (len == 0) {
		/* Special case where expansion evaluates to empty */
		cn->cn_flags = CF_EXPANDED;
		cn->cn_value_expanded = NULL;
		result = "";
		goto done;
	}

	buf = malloc(len);
	done_len = process_config_value(cn->cn_value_raw, buf, len, depth);
	VERIFY3U(len, ==, done_len);

	cn->cn_flags = CF_EXPANDED;
	cn->cn_value_expanded = buf;
	result = buf;

done:
	if (depth == 0) {
		pthread_mutex_unlock(&config_lock);
	}
	return (result);
}

const char *
get_config_value(const char *path)
{
	config_node_t *cn;

	cn = find_config_path(path, NULL);
	if (cn != NULL) {
		return (expand_config_value(cn, 0));
	}
	return (NULL);
}

static config_node_t *
find_config_path(const char *path, avl_index_t *idx)
{
	config_node_t search;

	search.cn_path = path;
	return (avl_find(&config_tree, &search, idx));
}

static config_node_t *
set_config_raw(const char *path, const char *value)
{
	config_node_t *cn;
	avl_index_t idx;

	ASSERT(pthread_mutex_isowned_np(&config_lock));
	VERIFY(!config_finished);

	cn = find_config_path(path, &idx);

	if (cn != NULL) {
		/* overwrite node */
		cn->cn_flags = 0;
		free((void *)cn->cn_value_raw);
		free((void *)cn->cn_value_expanded);
		cn->cn_value_raw = strdup(value);
		cn->cn_value_expanded = NULL;
		if (cn->cn_value_raw == NULL) {
			goto alloc_err;
		}
	} else {
		/* insert node */
		char *dpath, *dvalue;

		cn = calloc(1, sizeof (*cn));
		dpath = strdup(path);
		dvalue = strdup(value);
		if (cn == NULL || dpath == NULL || dvalue == NULL) {
			goto alloc_err;
		}
		cn->cn_path = dpath;
		cn->cn_value_raw = dvalue;
		avl_insert(&config_tree, cn, idx);
	}

	if (strstr(cn->cn_value_raw, "%") != NULL) {
		cn->cn_flags |= CF_NEEDS_EXPAND;
	}
	return (cn);

alloc_err:
	err(4, "Could not allocate memory");
	return (NULL); /* not reached */
}

void
set_config_value(const char *path, const char *value)
{
	pthread_mutex_lock(&config_lock);
	(void) set_config_raw(path, value);
	pthread_mutex_unlock(&config_lock);
}

void
set_config_bool(const char *path, boolean_t value)
{
	config_node_t *cn;

	pthread_mutex_lock(&config_lock);
	cn = set_config_raw(path, value ? "true" : "false");
	cn->cn_bool = value;
	cn->cn_flags |= CF_BOOL_CHECKED;
	pthread_mutex_unlock(&config_lock);
}

boolean_t
get_config_bool(const char *path)
{
	config_node_t *cn;

	cn = find_config_path(path, NULL);
	if (cn == NULL) {
		/* XXX: strictness? */
		return (B_FALSE);
	}

	if (cn->cn_flags & CF_BOOL_CHECKED) {
		return (cn->cn_bool);
	} else {
		const char *value;
		boolean_t valid = B_FALSE;
		boolean_t bval = B_FALSE;

		value = expand_config_value(cn, 0);
		if (strcasecmp(value, "true") == 0 ||
		    strcasecmp(value, "on") == 0 ||
		    strcasecmp(value, "yes") == 0 ||
		    strcmp(value, "1") == 0) {
			bval = B_TRUE;
			valid = B_TRUE;
		} else if (strcasecmp(value, "false") == 0 ||
		    strcasecmp(value, "off") == 0 ||
		    strcasecmp(value, "no") == 0 ||
		    strcmp(value, "0") == 0) {
			bval = B_FALSE;
			valid = B_TRUE;
		}

		if (valid) {
			pthread_mutex_lock(&config_lock);
			cn->cn_bool = bval;
			cn->cn_flags |= CF_BOOL_CHECKED;
			pthread_mutex_unlock(&config_lock);
		} else {
			warnx("Invalid value %s for boolean variable %s",
			    value, path);
		}
		return (bval);
	}
}

void
dump_config(boolean_t do_expand)
{
	avl_tree_t *tree = &config_tree;
	config_node_t *cn;

	for (cn = avl_first(tree); cn != NULL; cn = AVL_NEXT(tree, cn)) {
		const char *value;

		if (do_expand) {
			value = expand_config_value(cn, 0);
		} else {
			value = cn->cn_value_raw;
		}
		printf("%s=%s\n", cn->cn_path, value);
	}
}
