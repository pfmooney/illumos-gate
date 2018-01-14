#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#
# Copyright (c) 2018, Joyent, Inc.
#

include $(SRC)/cmd/Makefile.cmd
include ../Makefile.bhyve
include $(SRC)/cmd/Makefile.cmd.64

PROGS =		attach detach statechange uninstall

PROG1 =		boot
OBJS1 =		boot.o
PROGS +=	$(PROG1)
OBJS +=		$(OBJS1)
CLEANFILES +=	$(PROG1) $(OBJS1)
$(PROG1) :=	LDLIBS += -lnvpair

TEMPLATES =	SYSbhyve.xml
XMLDOCS =	config.xml platform.xml
CLOBBERFILES =	$(ROOTXMLDOCS) $(ROOTTEMPLATES) $(ROOTPROGS)

# This shouldn't be necessary, but for some reason the same thing in
# ../../Makefile.brand is not being picked up.
$(ROOTPROGS) :=	FILEMODE = 755

all: $(PROGS)

$(PROG1): $(OBJS1)
	$(LINK.c) -o $@ $(OBJS1) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

install: $(ROOTPROGS) $(ROOTXMLDOCS) $(ROOTTEMPLATES)

clean:
	$(RM) $(CLEANFILES)

lint:

include $(SRC)/cmd/Makefile.targ
