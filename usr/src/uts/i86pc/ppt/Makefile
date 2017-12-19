#
# COPYRIGHT 2013 Pluribus Networks Inc.
#
# All rights reserved. This copyright notice is Copyright Management
# Information under 17 USC 1202 and is included to protect this work and
# deter copyright infringement.  Removal or alteration of this Copyright
# Management Information without the express written permission from
# Pluribus Networks Inc is prohibited, and any such unauthorized removal
# or alteration will be a violation of federal law.

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= ppt
OBJECTS		= $(PPT_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(PPT_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/i86pc/io/vmm/io

#
#	Include common rules.
#
include $(UTSBASE)/i86pc/Makefile.i86pc

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
#	Overrides and additions
#
ALL_BUILDS	= $(ALL_BUILDSONLY64)
DEF_BUILDS	= $(DEF_BUILDSONLY64)
PRE_INC_PATH	= -I$(COMPAT)/freebsd -I$(COMPAT)/freebsd/amd64 \
	-I$(CONTRIB)/freebsd -I$(CONTRIB)/freebsd/amd64
INC_PATH	+= -I$(UTSBASE)/i86pc/io/vmm -I$(UTSBASE)/i86pc/io/vmm/io
AS_INC_PATH	+= -I$(UTSBASE)/i86pc/io/vmm -I$(OBJS_DIR)

LDFLAGS         += -dy -N drv/vmm -N misc/pcie

$(OBJS_DIR)/ppt.o := CERRWARN	+= -_gcc=-Wno-unused-variable

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

#
#	Include common targets.
#
include $(UTSBASE)/i86pc/Makefile.targ
