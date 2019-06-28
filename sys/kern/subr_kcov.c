/*	$NetBSD: subr_kcov.c,v 1.8 2019/05/26 05:41:45 kamil Exp $	*/

/*
 * Copyright (c) 2019 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Siddharth Muralee.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <sys/module.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>

#include <sys/atomic.h>
#include <sys/conf.h>
#include <sys/condvar.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kmem.h>
#include <sys/mman.h>
#include <sys/mutex.h>
#include <sys/queue.h>

#include <uvm/uvm_extern.h>
#include <sys/kcov.h>

volatile unsigned int opened_fds;

static struct kcov_ops *ops;

#define KCOV_OPEN() (ops->open)()
#define KCOV_FREE(k) (ops->free)(k)
#define KCOV_SETBUFSIZE(k, nent) (ops->setbufsize)(k, nent)
#define KCOV_ENABLE(k, mode) (ops->enable)(k, mode)
#define KCOV_DISABLE(k) (ops->disable)(k)
#define KCOV_MMAP(k, size, off, uobjp) (ops->mmap)(k, size, off, uobjp)
#define KCOV_COV_TRACE_PC(k, pc) (ops->cov_trace_pc)(k, pc)
#define KCOV_COV_TRACE_CMP(k, t, a, b, pc) (ops->cov_trace_cmp)(k, t, a, b, pc)

/*
 * KCOV RAW, the default mode with full trace.
 */
static struct kcov_ops kcov_raw_ops;

#define KCOV_BUF_MAX_ENTRIES	(256 << 10)

#define KCOV_CMP_CONST		1
#define KCOV_CMP_SIZE(x)	((x) << 1)

static dev_type_open(kcov_open);

const struct cdevsw kcov_cdevsw = {
	.d_open = kcov_open,
	.d_close = noclose,
	.d_read = noread,
	.d_write = nowrite,
	.d_ioctl = noioctl,
	.d_stop = nostop,
	.d_tty = notty,
	.d_poll = nopoll,
	.d_mmap = nommap,
	.d_kqfilter = nokqfilter,
	.d_discard = nodiscard,
	.d_flag = D_OTHER | D_MPSAFE
};

static int kcov_fops_ioctl(file_t *, u_long, void *);
static int kcov_fops_close(file_t *);
static int kcov_fops_mmap(file_t *, off_t *, size_t, int, int *, int *,
    struct uvm_object **, int *);

const struct fileops kcov_fileops = {
	.fo_read = fbadop_read,
	.fo_write = fbadop_write,
	.fo_ioctl = kcov_fops_ioctl,
	.fo_fcntl = fnullop_fcntl,
	.fo_poll = fnullop_poll,
	.fo_stat = fbadop_stat,
	.fo_close = kcov_fops_close,
	.fo_kqfilter = fnullop_kqfilter,
	.fo_restart = fnullop_restart,
	.fo_mmap = kcov_fops_mmap,
};

/*
 * The KCOV descriptors (KD) are allocated during open(), and are associated
 * with a file descriptor.
 *
 * An LWP can 'enable' a KD. When this happens, this LWP becomes the owner of
 * the KD, and no LWP can 'disable' this KD except the owner.
 *
 * A KD is freed when its file descriptor is closed _iff_ the KD is not active
 * on an LWP. If it is, we ask the LWP to free it when it exits.
 *
 * The buffers mmapped are in a dedicated uobj, therefore there is no risk
 * that the kernel frees a buffer still mmapped in a process: the uobj
 * refcount will be non-zero, so the backing is not freed until an munmap
 * occurs on said process.
 */

typedef struct kcov_desc {
	kmutex_t lock;
	void *priv;
	bool enabled;
	bool lwpfree;
} kcov_t;

static specificdata_key_t kcov_lwp_key;

static void
kcov_lock(kcov_t *kd)
{

	mutex_enter(&kd->lock);
}

static void
kcov_unlock(kcov_t *kd)
{

	mutex_exit(&kd->lock);
}

static void
kcov_free(kcov_t *kd)
{

	KASSERT(kd != NULL);
	mutex_destroy(&kd->lock);
	KCOV_FREE(kd->priv);
	kmem_free(kd, sizeof(*kd));
}

static void
kcov_lwp_free(void *arg)
{
	kcov_t *kd = (kcov_t *)arg;

	if (kd == NULL) {
		return;
	}
	kcov_lock(kd);
	kd->enabled = false;
	kcov_unlock(kd);
	if (kd->lwpfree) {
		kcov_free(kd);
	}
}

/* -------------------------------------------------------------------------- */

static int
kcov_open(dev_t dev, int flag, int mode, struct lwp *l)
{
	struct file *fp;
	int error, fd;
	kcov_t *kd;

	atomic_inc_uint(&opened_fds);

	error = fd_allocfile(&fp, &fd);
	if (error) {
		atomic_dec_uint(&opened_fds);
		return error;
	}

	kd = kmem_zalloc(sizeof(*kd), KM_SLEEP);
	mutex_init(&kd->lock, MUTEX_DEFAULT, IPL_NONE);

	kd->priv = KCOV_OPEN();

	return fd_clone(fp, fd, flag, &kcov_fileops, kd);
}

static int
kcov_fops_close(file_t *fp)
{
	kcov_t *kd = fp->f_data;

	kcov_lock(kd);
	if (kd->enabled) {
		kd->lwpfree = true;
		kcov_unlock(kd);
	} else {
		kcov_unlock(kd);
		kcov_free(kd);
	}
	fp->f_data = NULL;

	atomic_dec_uint(&opened_fds);

   	return 0;
}

static int
kcov_fops_ioctl(file_t *fp, u_long cmd, void *addr)
{
	int error = 0;
	kcov_t *kd;

	kd = fp->f_data;
	if (kd == NULL)
		return ENXIO;
	kcov_lock(kd);

	switch (cmd) {
	case KCOV_IOC_SETBUFSIZE:
		if (kd->enabled) {
			error = EBUSY;
			break;
		}
		error = KCOV_SETBUFSIZE(kd->priv, *((uint64_t *)addr));
		break;
	case KCOV_IOC_ENABLE:
		if (kd->enabled) {
			error = EBUSY;
			break;
		}
		if (lwp_getspecific(kcov_lwp_key) != NULL) {
			error = EBUSY;
			break;
		}

		error = KCOV_ENABLE(kd->priv, *((int *)addr));
		if (error)
			break;

		lwp_setspecific(kcov_lwp_key, kd);
		kd->enabled = true;
		break;
	case KCOV_IOC_DISABLE:
		if (!kd->enabled) {
			error = ENOENT;
			break;
		}
		if (lwp_getspecific(kcov_lwp_key) != kd) {
			error = ENOENT;
			break;
		}

		error = KCOV_DISABLE(kd->priv);
		if (error)
			break;

		lwp_setspecific(kcov_lwp_key, NULL);
		kd->enabled = false;
		break;
	default:
		error = EINVAL;
	}

	kcov_unlock(kd);
	return error;
}

static int
kcov_fops_mmap(file_t *fp, off_t *offp, size_t size, int prot, int *flagsp,
    int *advicep, struct uvm_object **uobjp, int *maxprotp)
{
	off_t off = *offp;
	kcov_t *kd;
	int error = 0;

	if (prot & PROT_EXEC)
		return EACCES;
	if (off < 0)
		return EINVAL;
	if (size > KCOV_BUF_MAX_ENTRIES * KCOV_ENTRY_SIZE)
		return EINVAL;
	if (off > KCOV_BUF_MAX_ENTRIES * KCOV_ENTRY_SIZE)
		return EINVAL;

	kd = fp->f_data;
	if (kd == NULL)
		return ENXIO;
	kcov_lock(kd);

	error = KCOV_MMAP(kd->priv, size, off, uobjp);
	if (error)
		goto out;

	*maxprotp = prot;
	*advicep = UVM_ADV_RANDOM;

out:
	kcov_unlock(kd);
	return error;
}

static inline bool
in_interrupt(void)
{
	return curcpu()->ci_idepth >= 0;
}

void __sanitizer_cov_trace_pc(void);

void
__sanitizer_cov_trace_pc(void)
{
	extern int cold;
	kcov_t *kd;

	if (__predict_false(cold)) {
		/* Do not trace during boot. */
		return;
	}

	if (in_interrupt()) {
		/* Do not trace in interrupts. */
		return;
	}

	kd = lwp_getspecific(kcov_lwp_key);
	if (__predict_true(kd == NULL)) {
		/* Not traced. */
		return;
	}

	if (!kd->enabled) {
		/* Tracing not enabled */
		return;
	}

	KCOV_COV_TRACE_PC(kd->priv, (intptr_t)__builtin_return_address(0));
}

static void
trace_cmp(uint64_t type, uint64_t arg1, uint64_t arg2, intptr_t pc)
{
	extern int cold;
	kcov_t *kd;

	if (__predict_false(cold)) {
		/* Do not trace during boot. */
		return;
	}

	if (in_interrupt()) {
		/* Do not trace in interrupts. */
		return;
	}

	kd = lwp_getspecific(kcov_lwp_key);
	if (__predict_true(kd == NULL)) {
		/* Not traced. */
		return;
	}

	if (!kd->enabled) {
		/* Tracing not enabled */
		return;
	}

	KCOV_COV_TRACE_CMP(kd->priv, type, arg1, arg2, pc);
}

void __sanitizer_cov_trace_cmp1(uint8_t arg1, uint8_t arg2);

void
__sanitizer_cov_trace_cmp1(uint8_t arg1, uint8_t arg2)
{

	trace_cmp(KCOV_CMP_SIZE(0), arg1, arg2,
	    (intptr_t)__builtin_return_address(0));
}

void __sanitizer_cov_trace_cmp2(uint16_t arg1, uint16_t arg2);

void
__sanitizer_cov_trace_cmp2(uint16_t arg1, uint16_t arg2)
{

	trace_cmp(KCOV_CMP_SIZE(1), arg1, arg2,
	    (intptr_t)__builtin_return_address(0));
}

void __sanitizer_cov_trace_cmp4(uint32_t arg1, uint32_t arg2);

void
__sanitizer_cov_trace_cmp4(uint32_t arg1, uint32_t arg2)
{

	trace_cmp(KCOV_CMP_SIZE(2), arg1, arg2,
	    (intptr_t)__builtin_return_address(0));
}

void __sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2);

void
__sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2)
{

	trace_cmp(KCOV_CMP_SIZE(3), arg1, arg2,
	    (intptr_t)__builtin_return_address(0));
}

void __sanitizer_cov_trace_const_cmp1(uint8_t arg1, uint8_t arg2);

void
__sanitizer_cov_trace_const_cmp1(uint8_t arg1, uint8_t arg2)
{

	trace_cmp(KCOV_CMP_SIZE(0) | KCOV_CMP_CONST, arg1, arg2,
	    (intptr_t)__builtin_return_address(0));
}

void __sanitizer_cov_trace_const_cmp2(uint16_t arg1, uint16_t arg2);

void
__sanitizer_cov_trace_const_cmp2(uint16_t arg1, uint16_t arg2)
{

	trace_cmp(KCOV_CMP_SIZE(1) | KCOV_CMP_CONST, arg1, arg2,
	    (intptr_t)__builtin_return_address(0));
}

void __sanitizer_cov_trace_const_cmp4(uint32_t arg1, uint32_t arg2);

void
__sanitizer_cov_trace_const_cmp4(uint32_t arg1, uint32_t arg2)
{

	trace_cmp(KCOV_CMP_SIZE(2) | KCOV_CMP_CONST, arg1, arg2,
	    (intptr_t)__builtin_return_address(0));
}

void __sanitizer_cov_trace_const_cmp8(uint64_t arg1, uint64_t arg2);

void
__sanitizer_cov_trace_const_cmp8(uint64_t arg1, uint64_t arg2)
{

	trace_cmp(KCOV_CMP_SIZE(3) | KCOV_CMP_CONST, arg1, arg2,
	    (intptr_t)__builtin_return_address(0));
}

void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases);

void
__sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases)
{
	uint64_t i, nbits, ncases, type;
	intptr_t pc;

	pc = (intptr_t)__builtin_return_address(0);
	ncases = cases[0];
	nbits = cases[1];

	switch (nbits) {
	case 8:
		type = KCOV_CMP_SIZE(0);
		break;
	case 16:
		type = KCOV_CMP_SIZE(1);
		break;
	case 32:
		type = KCOV_CMP_SIZE(2);
		break;
	case 64:
		type = KCOV_CMP_SIZE(3);
		break;
	default:
		return;
	}
	type |= KCOV_CMP_CONST;

	for (i = 0; i < ncases; i++)
		trace_cmp(type, cases[i + 2], val, pc);
}

/* -------------------------------------------------------------------------- */

MODULE(MODULE_CLASS_MISC, kcov, NULL);

static void
kcov_init(void)
{

	lwp_specific_key_create(&kcov_lwp_key, kcov_lwp_free);

	ops = &kcov_raw_ops;
}

static int
kcov_modcmd(modcmd_t cmd, void *arg)
{

   	switch (cmd) {
	case MODULE_CMD_INIT:
		kcov_init();
		return 0;
	case MODULE_CMD_FINI:
		return EINVAL;
	default:
		return ENOTTY;
	}
}

int
kcov_ops_set(struct kcov_ops *o)
{

	KASSERT(o);
	KASSERT(o->free);
	KASSERT(o->setbufsize);
	KASSERT(o->enable);
	KASSERT(o->disable);
	KASSERT(o->mmap);
	KASSERT(o->cov_trace_pc);
	KASSERT(o->cov_trace_cmp);

	if (opened_fds > 0)
		return EBUSY;

	ops = o;

	return 0;
}

int
kcov_ops_unset(struct kcov_ops *o)
{

	KASSERT(o);

	if (opened_fds > 0)
		return EBUSY;

	/* Only allow to detach self */
	if (ops != o)
		return EINVAL;

	ops = &kcov_raw_ops;

	return 0;
}

/* -------------------------------------------------------------------------- */

typedef struct kcov_desc_raw {
	kcov_int_t *buf;
	struct uvm_object *uobj;
	size_t bufnent;
	size_t bufsize;
	int mode;
} kcov_raw_t;

static void *
kcov_raw_open(void)
{

	return kmem_zalloc(sizeof(kcov_raw_t), KM_SLEEP);
}

static void
kcov_raw_free(void *priv)
{
	kcov_raw_t *raw;

	raw = (kcov_raw_t *)priv;

	if (raw->buf != NULL) {
		uvm_deallocate(kernel_map, (vaddr_t)raw->buf, raw->bufsize);
	}

	kmem_free(raw, sizeof(*raw));
}

static int
kcov_raw_setbufsize(void *priv, uint64_t nent)
{
	kcov_raw_t *raw;
	size_t size;
	int error;

	raw = (kcov_raw_t *)priv;

	if (nent < 2 || nent > KCOV_BUF_MAX_ENTRIES)
		return EINVAL;
	if (raw->buf != NULL)
		return EEXIST;

	size = roundup(nent * KCOV_ENTRY_SIZE, PAGE_SIZE);
	raw->bufnent = nent - 1;
	raw->bufsize = size;
	raw->uobj = uao_create(raw->bufsize, 0);

	/* Map the uobj into the kernel address space, as wired. */
	raw->buf = NULL;
	error = uvm_map(kernel_map, (vaddr_t *)&raw->buf, raw->bufsize,
	    raw->uobj, 0, 0, UVM_MAPFLAG(UVM_PROT_RW, UVM_PROT_RW,
	    UVM_INH_SHARE, UVM_ADV_RANDOM, 0));
	if (error) {
		uao_detach(raw->uobj);
		return error;
	}
	error = uvm_map_pageable(kernel_map, (vaddr_t)raw->buf,
	    (vaddr_t)raw->buf + size, false, 0);
	if (error) {
		uvm_deallocate(kernel_map, (vaddr_t)raw->buf, size);
		return error;
	}

	return 0;
}

static int
kcov_raw_enable(void *priv, int mode)
{
	kcov_raw_t *raw;

	raw = (kcov_raw_t *)priv;

	if (raw->buf == NULL)
		return ENOBUFS;

	switch (mode) {
	case KCOV_MODE_NONE:
	case KCOV_MODE_TRACE_PC:
	case KCOV_MODE_TRACE_CMP:
		raw->mode = mode;
		return 0;
	default:
		return EINVAL;
	}
}

static int
kcov_raw_disable(void *priv __unused)
{

	return 0;
}

static int
kcov_raw_mmap(void *priv, size_t size, off_t off, struct uvm_object **uobjp)
{
	kcov_raw_t *raw;

	raw = (kcov_raw_t *)priv;

	if ((size + off) > raw->bufsize)
		return ENOMEM;

	uao_reference(raw->uobj);

	*uobjp = raw->uobj;

	return 0;
}

static void
kcov_raw_cov_trace_pc(void *priv, intptr_t pc)
{
	kcov_raw_t *raw;
	uint64_t idx;

	raw = (kcov_raw_t *)priv;

	if (raw->mode != KCOV_MODE_TRACE_PC) {
		/* PC tracing mode not enabled */
		return;
	}

	idx = raw->buf[0];
	if (idx < raw->bufnent) {
		raw->buf[idx+1] = pc;
		raw->buf[0] = idx + 1;
	}
}

static void
kcov_raw_cov_trace_cmp(void *priv, uint64_t type, uint64_t arg1, uint64_t arg2,
    intptr_t pc)
{
	kcov_raw_t *raw;
	uint64_t idx;

	raw = (kcov_raw_t *)priv;

	if (raw->mode != KCOV_MODE_TRACE_CMP) {
		/* CMP tracing mode not enabled */
		return;
	}

	idx = raw->buf[0];
	if ((idx * 4 + 4) <= raw->bufnent) {
		raw->buf[idx * 4 + 1] = type;
		raw->buf[idx * 4 + 2] = arg1;
		raw->buf[idx * 4 + 3] = arg2;
		raw->buf[idx * 4 + 4] = pc;
		raw->buf[0] = idx + 1;
	}
}

static struct kcov_ops kcov_raw_ops = {
	.open = kcov_raw_open,
	.free = kcov_raw_free,
	.setbufsize = kcov_raw_setbufsize,
	.enable = kcov_raw_enable,
	.disable = kcov_raw_disable,
	.mmap = kcov_raw_mmap,
	.cov_trace_pc = kcov_raw_cov_trace_pc,
	.cov_trace_cmp = kcov_raw_cov_trace_cmp
};
