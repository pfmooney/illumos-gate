/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2019 John H. Baldwin <jhb@FreeBSD.org>
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
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

static nvlist_t *config_root;

void
init_config(void)
{

	config_root = nvlist_create(0);
	if (config_root == NULL)
		err(4, "Failed to create configuration root nvlist");
}

nvlist_t *
lookup_config_node(const char *path, bool create)
{
	char *copy, *name, *tofree;
	nvlist_t *nvl, *new_nvl;

	copy = strdup(path);
	if (copy == NULL)
		errx(4, "Failed to allocate memory");
	tofree = copy;
	nvl = config_root;
	while ((name = strsep(&copy, ".")) != NULL) {
		if (*name == '\0') {
			warnx("Invalid configuration node: %s", path);
			nvl = NULL;
			break;
		}
		if (nvlist_exists_nvlist(nvl, name))
			nvl = (nvlist_t *)nvlist_get_nvlist(nvl, name);
		else if (nvlist_exists(nvl, name)) {
			for (copy = tofree; copy < name; copy++)
				if (*copy == '\0')
					*copy = '.';
			warnx(
		    "Configuration node %s is a child of existing variable %s",
			    path, tofree);
			nvl = NULL;
			break;
		} else if (create) {
			new_nvl = nvlist_create(0);
			if (new_nvl == NULL)
				errx(4, "Failed to allocate memory");
			nvlist_move_nvlist(nvl, name, new_nvl);
			nvl = new_nvl;
		} else {
			nvl = NULL;
			break;
		}
	}
	free(tofree);
	return (nvl);
}

void
set_config_value_node(nvlist_t *parent, const char *name, const char *value)
{

	if (parent == NULL)
		parent = config_root;
	if (nvlist_exists_string(parent, name))
		nvlist_free_string(parent, name);
	else if (nvlist_exists(parent, name))
		errx(4,
		    "Attemping to add value %s to existing node %s of list %p",
		    value, name, parent);
	nvlist_add_string(parent, name, value);
}

void
set_config_value(const char *path, const char *value)
{
	const char *name;
	char *node_name;
	nvlist_t *nvl;

	/* Look for last separator. */
	name = strrchr(path, '.');
	if (name == NULL) {
		nvl = config_root;
		name = path;
	} else {
		node_name = strndup(path, name - path);
		if (node_name == NULL)
			errx(4, "Failed to allocate memory");
		nvl = lookup_config_node(node_name, true);
		if (nvl == NULL)
			errx(4,
			    "Failed to create or lookup configuration node %s",
			    node_name);
		free(node_name);

		/* Skip over '.'. */
		name++;
	}

	if (nvlist_exists_nvlist(nvl, name))
		errx(4, "Attempting to add value %s to existing node %s",
		    value, path);
	set_config_value_node(nvl, name, value);
}

static const char *
get_raw_config_value(const char *path)
{
	const char *name;
	char *node_name;
	nvlist_t *nvl;

	/* Look for last separator. */
	name = strrchr(path, '.');
	if (name == NULL) {
		nvl = config_root;
		name = path;
	} else {
		node_name = strndup(path, name - path);
		if (node_name == NULL)
			errx(4, "Failed to allocate memory");
		nvl = lookup_config_node(node_name, false);
		free(node_name);
		if (nvl == NULL)
			return (NULL);

		/* Skip over '.'. */
		name++;
	}

	if (nvlist_exists_string(nvl, name))
		return (nvlist_get_string(nvl, name));
	if (nvlist_exists_nvlist(nvl, name))
		warnx("Attempting to fetch value of node %s", path);
	return (NULL);
}

static char *
_expand_config_value(const char *value, int depth)
{
	FILE *valfp;
	const char *cp, *vp;
	char *nestedval, *path, *valbuf;
	size_t valsize;

	valfp = open_memstream(&valbuf, &valsize);
	if (valfp == NULL)
		errx(4, "Failed to allocate memory");

	vp = value;
	while (*vp != '\0') {
		switch (*vp) {
		case '%':
			if (depth > 15) {
				warnx(
		    "Too many recursive references in configuration value");
				fputc('%', valfp);
				vp++;
				break;
			}				
			if (vp[1] != '(' || vp[2] == '\0')
				cp = NULL;
			else
				cp = strchr(vp + 2, ')');
			if (cp == NULL) {
				warnx(
			    "Invalid reference in configuration value \"%s\"",
				    value);
				fputc('%', valfp);
				vp++;
				break;
			}
			vp += 2;

			if (cp == vp) {
				warnx(
			    "Empty reference in configuration value \"%s\"",
				    value);
				vp++;
				break;
			}

			/* Allocate a C string holding the path. */
			path = strndup(vp, cp - vp);
			if (path == NULL)
				errx(4, "Failed to allocate memory");

			/* Advance 'vp' past the reference. */
			vp = cp + 1;

			/* Fetch the referenced value. */
			cp = get_raw_config_value(path);
			if (cp == NULL)
				warnx(
		    "Failed to fetch referenced configuration variable %s",
				    path);
			else {
				nestedval = _expand_config_value(cp, depth + 1);
				fputs(nestedval, valfp);
				free(nestedval);
			}
			free(path);
			break;
		case '\\':
			vp++;
			if (*vp == '\0') {
				warnx(
			    "Trailing \\ in configuration value \"%s\"",
				    value);
				break;
			}
			/* FALLTHROUGH */
		default:
			fputc(*vp, valfp);
			vp++;
			break;
		}
	}
	fclose(valfp);
	return (valbuf);
}

const char *
expand_config_value(const char *value)
{
	static char *valbuf;

	if (strchr(value, '%') == NULL)
		return (value);

	free(valbuf);
	valbuf = _expand_config_value(value, 0);
	return (valbuf);
}

const char *
get_config_value(const char *path)
{
	const char *value;

	value = get_raw_config_value(path);
	if (value == NULL)
		return (NULL);
	return (expand_config_value(value));
}

const char *
get_config_value_node(nvlist_t *parent, const char *name)
{

	if (parent == NULL)
		parent = config_root;
	if (nvlist_exists_nvlist(parent, name))
		warnx("Attempt to fetch value of node %s of list %p", name,
		    parent);
	if (!nvlist_exists_string(parent, name))
		return (NULL);

	return (expand_config_value(nvlist_get_string(parent, name)));
}

bool
get_config_bool(const char *path)
{
	const char *value;

	value = get_config_value(path);
	if (value == NULL)
		err(4, "Failed to fetch boolean variable %s", path);
	if (strcasecmp(value, "true") == 0 ||
	    strcasecmp(value, "on") == 0 ||
	    strcasecmp(value, "yes") == 0 ||
	    strcmp(value, "1") == 0)
		return (true);
	if (strcasecmp(value, "false") == 0 ||
	    strcasecmp(value, "off") == 0 ||
	    strcasecmp(value, "no") == 0 ||
	    strcmp(value, "0") == 0)
		return (false);
	err(4, "Invalid value %s for boolean variable %s", value, path);
}

void
set_config_bool(const char *path, bool value)
{

	set_config_value(path, value ? "true" : "false");
}

void
dump_config(void)
{
	const nvlist_t *nvl;
	void *cookie;
	const char *name, *value, *expval;
	unsigned int depth;
	int type;

	nvl = config_root;
	cookie = NULL;
	depth = 0;
	for (;;) {
		while ((name = nvlist_next(nvl, &type, &cookie)) != NULL) {
			printf("%*s%s", (int)(depth * 4), "", name);
			if (type == NV_TYPE_NVLIST) {
				depth++;
				nvl = nvlist_get_nvlist(nvl, name);
				cookie = NULL;
			} else {
				assert(type == NV_TYPE_STRING);
				value = nvlist_get_string(nvl, name);
				printf("=%s", value);
				expval = expand_config_value(value);
				if (strcmp(value, expval) != 0)
					printf(" (%s)", expval);
			}
			printf("\n");
		}

		nvl = nvlist_get_parent(nvl, &cookie);
		if (nvl == NULL)
			break;
		depth--;
	}
}
