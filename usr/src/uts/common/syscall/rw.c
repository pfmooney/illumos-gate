/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015, Joyent, Inc.  All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include <sys/param.h>
#include <sys/isa_defs.h>
#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/sysmacros.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/cpuvar.h>
#include <sys/uio.h>
#include <sys/debug.h>
#include <sys/rctl.h>
#include <sys/nbmlock.h>
#include <sys/limits.h>

#define	COPYOUT_MAX_CACHE	(1<<17)		/* 128K */

size_t copyout_max_cached = COPYOUT_MAX_CACHE;	/* global so it's patchable */


static int iovec_copyin(void *, int, iovec_t *, ssize_t *);
int read_common(file_t *, uio_t *, size_t *, boolean_t);
int write_common(file_t *, uio_t *, size_t *, boolean_t);


/*
 * read, write, pread, pwrite, readv, and writev syscalls.
 *
 * 64-bit open:	all open's are large file opens.
 * Large Files: the behaviour of read depends on whether the fd
 *		corresponds to large open or not.
 * 32-bit open:	FOFFMAX flag not set.
 *		read until MAXOFF32_T - 1 and read at MAXOFF32_T returns
 *		EOVERFLOW if count is non-zero and if size of file
 *		is > MAXOFF32_T. If size of file is <= MAXOFF32_T read
 *		at >= MAXOFF32_T returns EOF.
 */

/*
 * Native system call
 */
ssize_t
read(int fdes, void *cbuf, size_t ccount)
{
	struct uio auio;
	struct iovec aiov;
	file_t *fp;
	ssize_t count = (ssize_t)ccount;
	size_t nread = 0;
	int fflag, error = 0;

	if (count < 0)
		return (set_errno(EINVAL));
	if ((fp = getf(fdes)) == NULL)
		return (set_errno(EBADF));
	if (((fflag = fp->f_flag) & FREAD) == 0) {
		error = EBADF;
		goto out;
	}
	if (fp->f_vnode->v_type == VREG && count == 0) {
		goto out;
	}

	aiov.iov_base = cbuf;
	aiov.iov_len = count;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = fp->f_offset;
	auio.uio_resid = count;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = MAXOFFSET_T;
	auio.uio_fmode = fflag;
	if (count <= copyout_max_cached)
		auio.uio_extflg = UIO_COPY_CACHED;
	else
		auio.uio_extflg = UIO_COPY_DEFAULT;

	error = read_common(fp, &auio, &nread, B_FALSE);

	if (error == EINTR && nread != 0)
		error = 0;
out:
	releasef(fdes);
	if (error)
		return (set_errno(error));
	return ((ssize_t)nread);
}

/*
 * Native system call
 */
ssize_t
write(int fdes, void *cbuf, size_t ccount)
{
	struct uio auio;
	struct iovec aiov;
	file_t *fp;
	ssize_t count = (ssize_t)ccount;
	size_t nwrite = 0;
	int fflag, error = 0;

	if (count < 0)
		return (set_errno(EINVAL));
	if ((fp = getf(fdes)) == NULL)
		return (set_errno(EBADF));
	if (((fflag = fp->f_flag) & FWRITE) == 0) {
		error = EBADF;
		goto out;
	}
	if (fp->f_vnode->v_type == VREG && count == 0) {
		goto out;
	}

	aiov.iov_base = cbuf;
	aiov.iov_len = count;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = fp->f_offset;
	auio.uio_resid = count;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = curproc->p_fsz_ctl;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_DEFAULT;

	error = write_common(fp, &auio, &nwrite, B_FALSE);

	if (error == EINTR && nwrite != 0)
		error = 0;
out:
	releasef(fdes);
	if (error)
		return (set_errno(error));
	return (nwrite);
}

ssize_t
pread(int fdes, void *cbuf, size_t ccount, off_t offset)
{
	struct uio auio;
	struct iovec aiov;
	file_t *fp;
	ssize_t count = (ssize_t)ccount;
	size_t nread = 0;
	int fflag, error = 0;
#ifdef _SYSCALL32_IMPL
	u_offset_t maxoff = get_udatamodel() == DATAMODEL_ILP32 ?
	    MAXOFF32_T : MAXOFFSET_T;
#else
	const u_offset_t maxoff = MAXOFF32_T;
#endif

	if (count < 0)
		return (set_errno(EINVAL));
	if ((fp = getf(fdes)) == NULL)
		return (set_errno(EBADF));
	if (((fflag = fp->f_flag) & FREAD) == 0) {
		error = EBADF;
		goto out;
	}
	if (fp->f_vnode->v_type == VREG) {
		u_offset_t fileoff = (u_offset_t)(ulong_t)offset;

		if (count == 0)
			goto out;
		/*
		 * Return EINVAL if an invalid offset comes to pread.
		 * Negative offset from user will cause this error.
		 */
		if (fileoff > maxoff) {
			error = EINVAL;
			goto out;
		}
		/*
		 * Limit offset such that we don't read or write
		 * a file beyond the maximum offset representable in
		 * an off_t structure.
		 */
		if (fileoff + count > maxoff)
			count = (ssize_t)((offset_t)maxoff - fileoff);
	} else if (fp->f_vnode->v_type == VFIFO) {
		error = ESPIPE;
		goto out;
	}

	aiov.iov_base = cbuf;
	aiov.iov_len = count;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = offset;
	auio.uio_resid = count;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = MAXOFFSET_T;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_CACHED;

	error = read_common(fp, &auio, &nread, B_TRUE);

	if (error == EINTR && nread != 0)
		error = 0;
out:
	releasef(fdes);
	if (error)
		return (set_errno(error));
	return ((ssize_t)nread);

}

ssize_t
pwrite(int fdes, void *cbuf, size_t ccount, off_t offset)
{
	struct uio auio;
	struct iovec aiov;
	file_t *fp;
	ssize_t count = (ssize_t)ccount;
	size_t nwrite = 0;
	int fflag, error = 0;
#ifdef _SYSCALL32_IMPL
	u_offset_t maxoff = get_udatamodel() == DATAMODEL_ILP32 ?
	    MAXOFF32_T : MAXOFFSET_T;
#else
	const u_offset_t maxoff = MAXOFF32_T;
#endif

	if (count < 0)
		return (set_errno(EINVAL));
	if ((fp = getf(fdes)) == NULL)
		return (set_errno(EBADF));
	if (((fflag = fp->f_flag) & (FWRITE)) == 0) {
		error = EBADF;
		goto out;
	}
	if (fp->f_vnode->v_type == VREG) {
		u_offset_t fileoff = (u_offset_t)(ulong_t)offset;

		if (count == 0)
			goto out;
		/*
		 * return EINVAL for offsets that cannot be
		 * represented in an off_t.
		 */
		if (fileoff > maxoff) {
			error = EINVAL;
			goto out;
		}
		/*
		 * Take appropriate action if we are trying to write above the
		 * resource limit.
		 */
		if (fileoff >= curproc->p_fsz_ctl) {
			mutex_enter(&curproc->p_lock);
			(void) rctl_action(rctlproc_legacy[RLIMIT_FSIZE],
			    curproc->p_rctls, curproc, RCA_UNSAFE_SIGINFO);
			mutex_exit(&curproc->p_lock);

			error = EFBIG;
			goto out;
		}
		/*
		 * Don't allow pwrite to cause file sizes to exceed
		 * maxoff.
		 */
		if (fileoff == maxoff) {
			error = EFBIG;
			goto out;
		}
		if (fileoff + count > maxoff)
			count = (ssize_t)((u_offset_t)maxoff - fileoff);
	} else if (fp->f_vnode->v_type == VFIFO) {
		error = ESPIPE;
		goto out;
	}

	aiov.iov_base = cbuf;
	aiov.iov_len = count;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = offset;
	auio.uio_resid = count;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = curproc->p_fsz_ctl;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_CACHED;

	error = write_common(fp, &auio, &nwrite, B_TRUE);

	if (error == EINTR && nwrite != 0)
		error = 0;
out:
	releasef(fdes);
	if (error)
		return (set_errno(error));
	return (nwrite);
}

ssize_t
readv(int fdes, struct iovec *iovp, int iovcnt)
{
	struct uio auio;
	struct iovec buf[IOV_MAX_STACK], *aiov = buf;
	int aiovlen = 0;
	file_t *fp;
	ssize_t count;
	size_t nread = 0;
	int fflag, error = 0;

	if (iovcnt <= 0 || iovcnt > IOV_MAX)
		return (set_errno(EINVAL));

	if (iovcnt > IOV_MAX_STACK) {
		aiovlen = iovcnt * sizeof (iovec_t);
		aiov = kmem_alloc(aiovlen, KM_SLEEP);
	}
	if ((error = iovec_copyin(iovp, iovcnt, aiov, &count)) != 0) {
		if (aiovlen != 0)
			kmem_free(aiov, aiovlen);
		return (set_errno(error));
	}

	if ((fp = getf(fdes)) == NULL) {
		if (aiovlen != 0)
			kmem_free(aiov, aiovlen);
		return (set_errno(EBADF));
	}
	if (((fflag = fp->f_flag) & FREAD) == 0) {
		error = EBADF;
		goto out;
	}
	if (fp->f_vnode->v_type == VREG && count == 0) {
		goto out;
	}

	auio.uio_iov = aiov;
	auio.uio_iovcnt = iovcnt;
	auio.uio_loffset = fp->f_offset;
	auio.uio_resid = count;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = MAXOFFSET_T;
	auio.uio_fmode = fflag;
	if (count <= copyout_max_cached)
		auio.uio_extflg = UIO_COPY_CACHED;
	else
		auio.uio_extflg = UIO_COPY_DEFAULT;

	error = read_common(fp, &auio, &nread, B_FALSE);

	if (error == EINTR && nread != 0)
		error = 0;
out:
	releasef(fdes);
	if (aiovlen != 0)
		kmem_free(aiov, aiovlen);
	if (error)
		return (set_errno(error));
	return (nread);
}

ssize_t
writev(int fdes, struct iovec *iovp, int iovcnt)
{
	struct uio auio;
	struct iovec buf[IOV_MAX_STACK], *aiov = buf;
	int aiovlen = 0;
	file_t *fp;
	ssize_t count;
	size_t nwrite = 0;
	int fflag, error = 0;

	if (iovcnt <= 0 || iovcnt > IOV_MAX)
		return (set_errno(EINVAL));
	if (iovcnt > IOV_MAX_STACK) {
		aiovlen = iovcnt * sizeof (iovec_t);
		aiov = kmem_alloc(aiovlen, KM_SLEEP);
	}
	if ((error = iovec_copyin(iovp, iovcnt, aiov, &count)) != 0) {
		if (aiovlen != 0)
			kmem_free(aiov, aiovlen);
		return (set_errno(error));
	}

	if ((fp = getf(fdes)) == NULL) {
		if (aiovlen != 0)
			kmem_free(aiov, aiovlen);
		return (set_errno(EBADF));
	}
	if (((fflag = fp->f_flag) & FWRITE) == 0) {
		error = EBADF;
		goto out;
	}
	if (fp->f_vnode->v_type == VREG && count == 0) {
		goto out;
	}

	auio.uio_iov = aiov;
	auio.uio_iovcnt = iovcnt;
	auio.uio_loffset = fp->f_offset;
	auio.uio_resid = count;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = curproc->p_fsz_ctl;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_DEFAULT;

	error = write_common(fp, &auio, &nwrite, B_FALSE);

	if (error == EINTR && nwrite != 0)
		error = 0;
out:
	releasef(fdes);
	if (aiovlen != 0)
		kmem_free(aiov, aiovlen);
	if (error)
		return (set_errno(error));
	return (nwrite);
}

ssize_t
preadv(int fdes, struct iovec *iovp, int iovcnt, off_t offset,
    off_t extended_offset)
{
	struct uio auio;
	struct iovec buf[IOV_MAX_STACK], *aiov = buf;
	int aiovlen = 0;
	file_t *fp;
	ssize_t count;
	size_t nread = 0;
	int fflag, error = 0;
#if defined(_SYSCALL32_IMPL) || defined(_ILP32)
	u_offset_t fileoff = ((u_offset_t)extended_offset << 32) |
	    (u_offset_t)offset;
#else /* _SYSCALL32_IMPL || _ILP32 */
	u_offset_t fileoff = (u_offset_t)(ulong_t)offset;
#endif /* _SYSCALL32_IMPR || _ILP32 */
#ifdef _SYSCALL32_IMPL
	const u_offset_t maxoff = get_udatamodel() == DATAMODEL_ILP32 &&
	    extended_offset == 0?
	    MAXOFF32_T : MAXOFFSET_T;
#else /* _SYSCALL32_IMPL */
	const u_offset_t maxoff = MAXOFF32_T;
#endif /* _SYSCALL32_IMPL */

	if (iovcnt <= 0 || iovcnt > IOV_MAX)
		return (set_errno(EINVAL));
	if (iovcnt > IOV_MAX_STACK) {
		aiovlen = iovcnt * sizeof (iovec_t);
		aiov = kmem_alloc(aiovlen, KM_SLEEP);
	}
	if ((error = iovec_copyin(iovp, iovcnt, aiov, &count)) != 0) {
		if (aiovlen != 0)
			kmem_free(aiov, aiovlen);
		return (set_errno(error));
	}

	if ((fp = getf(fdes)) == NULL) {
		if (aiovlen != 0)
			kmem_free(aiov, aiovlen);
		return (set_errno(EBADF));
	}
	if (((fflag = fp->f_flag) & FREAD) == 0) {
		error = EBADF;
		goto out;
	}
	if (fp->f_vnode->v_type == VREG) {
		if (count == 0)
			goto out;
		/*
		 * Return EINVAL if an invalid offset comes to pread.
		 * Negative offset from user will cause this error.
		 */
		if (fileoff > maxoff) {
			error = EINVAL;
			goto out;
		}
		/*
		 * Limit offset such that we don't read or write
		 * a file beyond the maximum offset representable in
		 * an off_t structure.
		 */
		if (fileoff + count > maxoff)
			count = (ssize_t)((offset_t)maxoff - fileoff);
	} else if (fp->f_vnode->v_type == VFIFO) {
		error = ESPIPE;
		goto out;
	}

	auio.uio_iov = aiov;
	auio.uio_iovcnt = iovcnt;
	auio.uio_loffset = fileoff;
	auio.uio_resid = count;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = MAXOFFSET_T;
	auio.uio_fmode = fflag;
	if (count <= copyout_max_cached)
		auio.uio_extflg = UIO_COPY_CACHED;
	else
		auio.uio_extflg = UIO_COPY_DEFAULT;

	error = read_common(fp, &auio, &nread, B_TRUE);

	if (error == EINTR && nread != 0)
		error = 0;
out:
	releasef(fdes);
	if (aiovlen != 0)
		kmem_free(aiov, aiovlen);
	if (error)
		return (set_errno(error));
	return (nread);
}

ssize_t
pwritev(int fdes, struct iovec *iovp, int iovcnt, off_t offset,
    off_t extended_offset)
{
	struct uio auio;
	struct iovec buf[IOV_MAX_STACK], *aiov = buf;
	int aiovlen = 0;
	file_t *fp;
	ssize_t count;
	size_t nwrite = 0;
	int fflag, error = 0;
#if defined(_SYSCALL32_IMPL) || defined(_ILP32)
	u_offset_t fileoff = ((u_offset_t)extended_offset << 32) |
	    (u_offset_t)offset;
#else /* _SYSCALL32_IMPL || _ILP32 */
	u_offset_t fileoff = (u_offset_t)(ulong_t)offset;
#endif /* _SYSCALL32_IMPR || _ILP32 */
#ifdef _SYSCALL32_IMPL
	const u_offset_t maxoff = get_udatamodel() == DATAMODEL_ILP32 &&
	    extended_offset == 0?
	    MAXOFF32_T : MAXOFFSET_T;
#else /* _SYSCALL32_IMPL */
	const u_offset_t maxoff = MAXOFF32_T;
#endif /* _SYSCALL32_IMPL */

	if (iovcnt <= 0 || iovcnt > IOV_MAX)
		return (set_errno(EINVAL));
	if (iovcnt > IOV_MAX_STACK) {
		aiovlen = iovcnt * sizeof (iovec_t);
		aiov = kmem_alloc(aiovlen, KM_SLEEP);
	}
	if ((error = iovec_copyin(iovp, iovcnt, aiov, &count)) != 0) {
		if (aiovlen != 0)
			kmem_free(aiov, aiovlen);
		return (set_errno(error));
	}

	if ((fp = getf(fdes)) == NULL) {
		if (aiovlen != 0)
			kmem_free(aiov, aiovlen);
		return (set_errno(EBADF));
	}
	if (((fflag = fp->f_flag) & FWRITE) == 0) {
		error = EBADF;
		goto out;
	}
	if (fp->f_vnode->v_type == VREG) {
		if (count == 0)
			goto out;
		/*
		 * return EINVAL for offsets that cannot be
		 * represented in an off_t.
		 */
		if (fileoff > maxoff) {
			error = EINVAL;
			goto out;
		}
		/*
		 * Take appropriate action if we are trying
		 * to write above the resource limit.
		 */
		if (fileoff >= curproc->p_fsz_ctl) {
			mutex_enter(&curproc->p_lock);
			/*
			 * Return value ignored because it lists
			 * actions taken, but we are in an error case.
			 * We don't have any actions that depend on
			 * what could happen in this call, so we ignore
			 * the return value.
			 */
			(void) rctl_action(
			    rctlproc_legacy[RLIMIT_FSIZE],
			    curproc->p_rctls, curproc,
			    RCA_UNSAFE_SIGINFO);
			mutex_exit(&curproc->p_lock);

			error = EFBIG;
			goto out;
		}
		/*
		 * Don't allow pwritev to cause file sizes to exceed
		 * maxoff.
		 */
		if (fileoff == maxoff) {
			error = EFBIG;
			goto out;
		}

		if (fileoff + count > maxoff)
			count = (ssize_t)((u_offset_t)maxoff - fileoff);
	} else if (fp->f_vnode->v_type == VFIFO) {
		error = ESPIPE;
		goto out;
	}

	auio.uio_iov = aiov;
	auio.uio_iovcnt = iovcnt;
	auio.uio_loffset = fileoff;
	auio.uio_resid = count;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = curproc->p_fsz_ctl;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_CACHED;

	error = write_common(fp, &auio, &nwrite, B_TRUE);

	if (error == EINTR && nwrite != 0)
		error = 0;
out:
	releasef(fdes);
	if (aiovlen != 0)
		kmem_free(aiov, aiovlen);
	if (error)
		return (set_errno(error));
	return (nwrite);
}

#if defined(_SYSCALL32_IMPL) || defined(_ILP32)

/*
 * This syscall supplies 64-bit file offsets to 32-bit applications only.
 */
ssize32_t
pread64(int fdes, void *cbuf, size32_t ccount, uint32_t offset_1,
    uint32_t offset_2)
{
	struct uio auio;
	struct iovec aiov;
	file_t *fp;
	ssize_t count = (ssize_t)ccount;
	size_t nread = 0;
	int fflag, error = 0;
	u_offset_t fileoff;

#if defined(_LITTLE_ENDIAN)
	fileoff = ((u_offset_t)offset_2 << 32) | (u_offset_t)offset_1;
#else
	fileoff = ((u_offset_t)offset_1 << 32) | (u_offset_t)offset_2;
#endif

	if (count < 0 || count > INT32_MAX)
		return (set_errno(EINVAL));

	if ((fp = getf(fdes)) == NULL)
		return (set_errno(EBADF));
	if (((fflag = fp->f_flag) & FREAD) == 0) {
		error = EBADF;
		goto out;
	}
	if (fp->f_vnode->v_type == VREG) {
		if (count == 0)
			goto out;
		/* Same as pread. See comments in pread. */
		if (fileoff > MAXOFFSET_T) {
			error = EINVAL;
			goto out;
		}
		if ((fileoff + count) > MAXOFFSET_T)
			count = (ssize_t)(MAXOFFSET_T - fileoff);
	} else if (fp->f_vnode->v_type == VFIFO) {
		error = ESPIPE;
		goto out;
	}

	/*
	 * Note: File size can never be greater than MAXOFFSET_T.
	 * If ever we start supporting 128 bit files the code similar to the
	 * one in pread at this place should be here.  Here we avoid the
	 * unnecessary VOP_GETATTR() when we know that fileoff == MAXOFFSET_T
	 * implies that it is always greater than or equal to file size.
	 */
	aiov.iov_base = cbuf;
	aiov.iov_len = count;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = fileoff;
	auio.uio_resid = count;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = MAXOFFSET_T;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_CACHED;

	error = read_common(fp, &auio, &nread, B_TRUE);

	if (error == EINTR && nread != 0)
		error = 0;
out:
	releasef(fdes);
	if (error)
		return (set_errno(error));
	return (nread);
}

/*
 * This syscall supplies 64-bit file offsets to 32-bit applications only.
 */
ssize32_t
pwrite64(int fdes, void *cbuf, size32_t ccount, uint32_t offset_1,
    uint32_t offset_2)
{
	struct uio auio;
	struct iovec aiov;
	file_t *fp;
	ssize_t count = (ssize_t)ccount;
	size_t nwrite = 0;
	int fflag, error = 0;
	u_offset_t fileoff;

#if defined(_LITTLE_ENDIAN)
	fileoff = ((u_offset_t)offset_2 << 32) | (u_offset_t)offset_1;
#else
	fileoff = ((u_offset_t)offset_1 << 32) | (u_offset_t)offset_2;
#endif

	if (count < 0 || count > INT32_MAX)
		return (set_errno(EINVAL));
	if ((fp = getf(fdes)) == NULL)
		return (set_errno(EBADF));
	if (((fflag = fp->f_flag) & FWRITE) == 0) {
		error = EBADF;
		goto out;
	}
	if (fp->f_vnode->v_type == VREG) {
		if (count == 0)
			goto out;
		/* See comments in pwrite. */
		if (fileoff > MAXOFFSET_T) {
			error = EINVAL;
			goto out;
		}
		if (fileoff >= curproc->p_fsz_ctl) {
			mutex_enter(&curproc->p_lock);
			(void) rctl_action(rctlproc_legacy[RLIMIT_FSIZE],
			    curproc->p_rctls, curproc, RCA_SAFE);
			mutex_exit(&curproc->p_lock);
			error = EFBIG;
			goto out;
		}
		if (fileoff == MAXOFFSET_T) {
			error = EFBIG;
			goto out;
		}
		if (fileoff + count > MAXOFFSET_T)
			count = (ssize_t)((u_offset_t)MAXOFFSET_T - fileoff);
	} else if (fp->f_vnode->v_type == VFIFO) {
		error = ESPIPE;
		goto out;
	}

	aiov.iov_base = cbuf;
	aiov.iov_len = count;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = fileoff;
	auio.uio_resid = count;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = curproc->p_fsz_ctl;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_CACHED;

	error = write_common(fp, &auio, &nwrite, B_TRUE);

	if (error == EINTR && nwrite != 0)
		error = 0;
out:
	releasef(fdes);
	if (error)
		return (set_errno(error));
	return (nwrite);
}

#endif	/* _SYSCALL32_IMPL || _ILP32 */

#ifdef _SYSCALL32_IMPL
/*
 * Tail-call elimination of xxx32() down to xxx()
 *
 * A number of xxx32 system calls take a len (or count) argument and
 * return a number in the range [0,len] or -1 on error.
 * Given an ssize32_t input len, the downcall xxx() will return
 * a 64-bit value that is -1 or in the range [0,len] which actually
 * is a proper return value for the xxx32 call. So even if the xxx32
 * calls can be considered as returning a ssize32_t, they are currently
 * declared as returning a ssize_t as this enables tail-call elimination.
 *
 * The cast of len (or count) to ssize32_t is needed to ensure we pass
 * down negative input values as such and let the downcall handle error
 * reporting. Functions covered by this comments are:
 *
 * rw.c:           read32, write32, pread32, pwrite32, readv32, writev32.
 * socksyscall.c:  recv32, recvfrom32, send32, sendto32.
 * readlink.c:     readlink32.
 */

ssize_t
read32(int32_t fdes, caddr32_t cbuf, size32_t count)
{
	return (read(fdes,
	    (void *)(uintptr_t)cbuf, (ssize32_t)count));
}

ssize_t
write32(int32_t fdes, caddr32_t cbuf, size32_t count)
{
	return (write(fdes,
	    (void *)(uintptr_t)cbuf, (ssize32_t)count));
}

ssize_t
pread32(int32_t fdes, caddr32_t cbuf, size32_t count, off32_t offset)
{
	return (pread(fdes,
	    (void *)(uintptr_t)cbuf, (ssize32_t)count,
	    (off_t)(uint32_t)offset));
}

ssize_t
pwrite32(int32_t fdes, caddr32_t cbuf, size32_t count, off32_t offset)
{
	return (pwrite(fdes,
	    (void *)(uintptr_t)cbuf, (ssize32_t)count,
	    (off_t)(uint32_t)offset));
}

ssize_t
readv32(int32_t fdes, caddr32_t iovp, int32_t iovcnt)
{
	return (readv(fdes, (void *)(uintptr_t)iovp, iovcnt));
}

ssize_t
writev32(int32_t fdes, caddr32_t iovp, int32_t iovcnt)
{
	return (writev(fdes, (void *)(uintptr_t)iovp, iovcnt));
}
#endif	/* _SYSCALL32_IMPL */

/* Common routines */

static int
iovec_copyin(void *uiovp, int iovcnt, iovec_t *kiovp, ssize_t *count)
{
#ifdef _SYSCALL32_IMPL
	/*
	 * 32-bit callers need to have their iovec expanded, while ensuring
	 * that they can't move more than 2Gbytes of data in a single call.
	 */
	if (get_udatamodel() == DATAMODEL_ILP32) {
		struct iovec32 buf32[IOV_MAX_STACK], *aiov32 = buf32;
		int aiov32len = 0;
		ssize32_t total32 = 0;
		int i;

		if (iovcnt > IOV_MAX_STACK) {
			aiov32len = iovcnt * sizeof (iovec32_t);
			aiov32 = kmem_alloc(aiov32len, KM_SLEEP);
		}

		if (copyin(uiovp, aiov32, iovcnt * sizeof (iovec32_t))) {
			if (aiov32len != 0) {
				kmem_free(aiov32, aiov32len);
			}
			return (EFAULT);
		}

		for (i = 0; i < iovcnt; i++) {
			ssize32_t iovlen32 = aiov32[i].iov_len;
			total32 += iovlen32;
			if (iovlen32 < 0 || total32 < 0) {
				if (aiov32len != 0) {
					kmem_free(aiov32, aiov32len);
				}
				return (EINVAL);
			}
			kiovp[i].iov_len = iovlen32;
			kiovp[i].iov_base =
			    (caddr_t)(uintptr_t)aiov32[i].iov_base;
		}
		*count = total32;

		if (aiov32len != 0)
			kmem_free(aiov32, aiov32len);
	} else
#endif
	{
		ssize_t total = 0;
		int i;

		if (copyin(uiovp, kiovp, iovcnt * sizeof (iovec_t)))
			return (EFAULT);
		for (i = 0; i < iovcnt; i++) {
			ssize_t iovlen = kiovp[i].iov_len;
			total += iovlen;
			if (iovlen < 0 || total < 0) {
				return (EINVAL);
			}
		}
		*count = total;
	}
	return (0);
}

int
read_common(file_t *fp, uio_t *uiop, size_t *nread, boolean_t positioned)
{
	vnode_t *vp = fp->f_vnode;
	int error = 0, rwflag = 0, ioflag;
	ssize_t count = uiop->uio_resid;
	size_t rcount = 0;
	struct cpu *cp;
	boolean_t in_crit = B_FALSE;

	/*
	 * We have to enter the critical region before calling VOP_RWLOCK
	 * to avoid a deadlock with ufs.
	 */
	if (nbl_need_check(vp)) {
		int svmand;

		nbl_start_crit(vp, RW_READER);
		in_crit = 1;
		error = nbl_svmand(vp, fp->f_cred, &svmand);
		if (error != 0)
			goto out;
		if (nbl_conflict(vp, NBL_READ, uiop->uio_offset, count, svmand,
		    NULL) != 0) {
			error = EACCES;
			goto out;
		}
	}

	(void) VOP_RWLOCK(vp, rwflag, NULL);
	/*
	 * For non-positioned reads, recheck offset/count validity inside
	 * VOP_WRLOCK to prevent filesize from changing during validation.
	 */
	if (!positioned) {
		u_offset_t uoffset = (u_offset_t)(ulong_t)fp->f_offset;

		if ((vp->v_type == VREG) && (uoffset >= OFFSET_MAX(fp))) {
			struct vattr va;

			va.va_mask = AT_SIZE;
			error = VOP_GETATTR(vp, &va, 0, fp->f_cred, NULL);
			VOP_RWUNLOCK(vp, rwflag, NULL);
			if (error != 0)
				goto out;
			/* We have to return EOF if fileoff is >= file size. */
			if (uoffset >= va.va_size)
				goto out;
			/*
			 * File is greater than or equal to maxoff and
			 * therefore we return EOVERFLOW.
			 */
			error = EOVERFLOW;
			goto out;
		}
		if ((vp->v_type == VREG) &&
		    (uoffset + count > OFFSET_MAX(fp))) {
			count = (ssize_t)(OFFSET_MAX(fp) - uoffset);
			uiop->uio_resid = count;
		}
		uiop->uio_offset = uoffset;
	}
	ioflag = uiop->uio_fmode & (FAPPEND|FSYNC|FDSYNC|FRSYNC);
	/* If read sync is not asked for, filter sync flags */
	if ((ioflag & FRSYNC) == 0)
		ioflag &= ~(FSYNC|FDSYNC);
	error = VOP_READ(vp, uiop, ioflag, fp->f_cred, NULL);
	rcount = count - uiop->uio_resid;
	CPU_STATS_ENTER_K();
	cp = CPU;
	CPU_STATS_ADDQ(cp, sys, sysread, 1);
	CPU_STATS_ADDQ(cp, sys, readch, (ulong_t)rcount);
	CPU_STATS_EXIT_K();
	ttolwp(curthread)->lwp_ru.ioch += (ulong_t)rcount;
	/* Store offset for non-positioned reads */
	if (!positioned) {
		if (vp->v_type == VFIFO) {
			/* Backward compatibility */
			fp->f_offset = rcount;
		} else if (((fp->f_flag & FAPPEND) == 0) ||
		    (vp->v_type != VREG) || (count != 0)) {
			/* POSIX */
			fp->f_offset = uiop->uio_loffset;
		}
	}
	VOP_RWUNLOCK(vp, rwflag, NULL);

out:
	if (in_crit)
		nbl_end_crit(vp);
	*nread = rcount;
	return (error);
}

int
write_common(file_t *fp, uio_t *uiop, size_t *nwrite, boolean_t positioned)
{
	vnode_t *vp = fp->f_vnode;
	int error = 0, rwflag = 1, ioflag;
	ssize_t count = uiop->uio_resid;
	size_t wcount = 0;
	struct cpu *cp;
	boolean_t in_crit = B_FALSE;

	/*
	 * We have to enter the critical region before calling VOP_RWLOCK
	 * to avoid a deadlock with ufs.
	 */
	if (nbl_need_check(vp)) {
		int svmand;

		nbl_start_crit(vp, RW_READER);
		in_crit = 1;
		error = nbl_svmand(vp, fp->f_cred, &svmand);
		if (error != 0)
			goto out;
		if (nbl_conflict(vp, NBL_WRITE, uiop->uio_loffset, count,
		    svmand, NULL) != 0) {
			error = EACCES;
			goto out;
		}
	}

	(void) VOP_RWLOCK(vp, rwflag, NULL);

	if (!positioned) {
		/*
		 * For non-positioned writes, the value of fp->f_offset is
		 * re-queried while inside VOP_RWLOCK.  This ensures that other
		 * writes which alter the filesize will be taken into account.
		 */
		uiop->uio_loffset = fp->f_offset;
		ioflag = uiop->uio_fmode & (FAPPEND|FSYNC|FDSYNC|FRSYNC);
	} else {
		/*
		 * The SUSv4 POSIX specification states:
		 * The pwrite() function shall be equivalent to write(), except
		 * that it writes into a given position and does not change
		 * the file offset (regardless of whether O_APPEND is set).
		 *
		 * To make this be true, we omit the FAPPEND flag from ioflag.
		 */
		ioflag = uiop->uio_fmode & (FSYNC|FDSYNC|FRSYNC);
	}
	if (vp->v_type == VREG) {
		u_offset_t fileoff = (u_offset_t)(ulong_t)uiop->uio_loffset;

		if (fileoff >= curproc->p_fsz_ctl) {
			VOP_RWUNLOCK(vp, rwflag, NULL);
			mutex_enter(&curproc->p_lock);
			(void) rctl_action(rctlproc_legacy[RLIMIT_FSIZE],
			    curproc->p_rctls, curproc, RCA_UNSAFE_SIGINFO);
			mutex_exit(&curproc->p_lock);
			error = EFBIG;
			goto out;
		}
		if (fileoff >= OFFSET_MAX(fp)) {
			VOP_RWUNLOCK(vp, rwflag, NULL);
			error = EFBIG;
			goto out;
		}
		if (fileoff + count > OFFSET_MAX(fp)) {
			count = (ssize_t)(OFFSET_MAX(fp) - fileoff);
			uiop->uio_resid = count;
		}
	}

	error = VOP_WRITE(vp, uiop, ioflag, fp->f_cred, NULL);
	wcount = count - uiop->uio_resid;
	CPU_STATS_ENTER_K();
	cp = CPU;
	CPU_STATS_ADDQ(cp, sys, syswrite, 1);
	CPU_STATS_ADDQ(cp, sys, writech, (ulong_t)wcount);
	CPU_STATS_EXIT_K();
	ttolwp(curthread)->lwp_ru.ioch += (ulong_t)wcount;

	/* Store offset for non-positioned writes */
	if (!positioned) {
		if (vp->v_type == VFIFO) {
			/* Backward compatibility */
			fp->f_offset = wcount;
		} else if (((fp->f_flag & FAPPEND) == 0) ||
		    (vp->v_type != VREG) || (count != 0)) {
			/* POSIX */
			fp->f_offset = uiop->uio_loffset;
		}
	}
	VOP_RWUNLOCK(vp, rwflag, NULL);

out:
	if (in_crit)
		nbl_end_crit(vp);
	*nwrite = wcount;
	return (error);
}
