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

/* For some tracing modes KCOV size needs to handle large stack/branch traces
 * use max value 512 MB
 */
#define KCOV_BUF_MAX_ENTRIES	(1 << 29)

/* AFL widely uses 64kB buffer for storing branch hits
 * KCOV will expose by default same size buffer ready to use
 * Size of buffer can be changed via KCOV_IOC_CHANGEAFLBUF IOCTL */
#define KCOV_AFLBUF_SDEFAULT	(1 << 16)

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
	kcov_int_t *buf;
	size_t bufsize;
	struct uvm_object *uobj;
	size_t bufnent;
	int mode;
	kmutex_t lock;
	uint8_t enabled : 1;
	uint8_t lwpfree : 1;
	kcov_module_t *submod;
} kcov_t;

static specificdata_key_t kcov_lwp_key;

typedef struct kcov_modules kcov_modules_t;

typedef struct kcov_modules {
	uint64_t id;
	kcov_modules_t *next;
	kcov_module_t *module;
} kcov_modules_t;

static kmutex_t modules_lock;

static kcov_modules_t kcov_modules = {
	0,
	NULL,
	NULL,
};

int
kcov_register_module(kcov_module_t *km, uint64_t *id)
{
	static kcov_modules_t *kp;

	mutex_enter(&modules_lock);

	kp = &kcov_modules;
	while (kp->next != NULL)
		kp = kp->next;

	kp->next = kmem_zalloc(sizeof(kcov_modules), KM_SLEEP);
	kp->next->id = kp->id+1;
	kp->next->next = NULL;
	kp->next->module = km;

	if (km->register_module != NULL)
		km->register_module(km);
	*id = kp->id+1;

	mutex_exit(&modules_lock);

	return 0;
};

int
kcov_unregister_module(uint64_t id)
{
	// TODO:: implement me
	return 0;
};

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
	if (kd->buf != NULL) {
		uvm_deallocate(kernel_map, (vaddr_t)kd->buf, kd->bufsize);
	}

	mutex_destroy(&kd->lock);
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
	kd->enabled = 0;
	kcov_unlock(kd);
	if (kd->lwpfree) {
		kcov_free(kd);
	}
}

static int
kcov_allocbuf(kcov_t *kd, uint64_t nent)
{
	size_t size;
	int error;

	if (nent < 2 || nent > KCOV_BUF_MAX_ENTRIES)
		return EINVAL;
	if (kd->buf != NULL)
		return EEXIST;

	size = roundup(nent * KCOV_ENTRY_SIZE, PAGE_SIZE);
	kd->bufnent = nent - 1;
	kd->bufsize = size;
	kd->uobj = uao_create(kd->bufsize, 0);

	/* Map the uobj into the kernel address space, as wired. */
	kd->buf = NULL;
	error = uvm_map(kernel_map, (vaddr_t *)&kd->buf, kd->bufsize, kd->uobj,
	    0, 0, UVM_MAPFLAG(UVM_PROT_RW, UVM_PROT_RW, UVM_INH_SHARE,
	    UVM_ADV_RANDOM, 0));
	if (error) {
		uao_detach(kd->uobj);
		return error;
	}
	error = uvm_map_pageable(kernel_map, (vaddr_t)kd->buf,
	    (vaddr_t)kd->buf + size, false, 0);
	if (error) {
		uvm_deallocate(kernel_map, (vaddr_t)kd->buf, size);
		return error;
	}

	return 0;
}


/* -------------------------------------------------------------------------- */

static int
kcov_open(dev_t dev, int flag, int mode, struct lwp *l)
{
	struct file *fp;
	int error, fd;
	kcov_t *kd;

	error = fd_allocfile(&fp, &fd);
	if (error)
		return error;

	kd = kmem_zalloc(sizeof(*kd), KM_SLEEP);
	mutex_init(&kd->lock, MUTEX_DEFAULT, IPL_NONE);

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

   	return 0;
}

static int
kcov_fops_ioctl(file_t *fp, u_long cmd, void *addr)
{
// TODO: handle submod via uid	uint64_t uid = 0;
	int error = 0;
	int mode;
	kcov_t *kd;

	kd = fp->f_data;
	if (kd == NULL)
		return ENXIO;
	kcov_lock(kd);
printf("#: MMPG: IOCTL(1)!: :: %lu \n", cmd);
	switch (cmd) {
	case KCOV_IOC_SETBUFSIZE:
		if (kd->enabled) {
			error = EBUSY;
			break;
		}
		error = kcov_allocbuf(kd, *((uint64_t *)addr));
		break;
// Move to AFL fd
//	case KCOV_IOC_CHANGEAFLBUF:
//		if (kd->enabled) {
//			error = EBUSY;
//			break;
//		}
//		error = kcov_realloc_aflbuf(kd, *((uint64_t *)addr));
//		break;
	case KCOV_IOC_ENABLE:
		if (kd->enabled) {
			error = EBUSY;
			break;
		}
		if (lwp_getspecific(kcov_lwp_key) != NULL) {
			error = EBUSY;
			break;
		}
		if (kd->buf == NULL) {
			error = ENOBUFS;
			break;
		}

		mode = *((int *)addr);
		switch (mode) {
		case KCOV_MODE_NONE:
		case KCOV_MODE_TRACE_PC:
		case KCOV_MODE_TRACE_CMP:
			kd->mode = mode;
			break;
		default:
			printf("#: MMPG : default#EINVAL\n");
			error = EINVAL;
		}
		if (error)
			break;

		lwp_setspecific(kcov_lwp_key, kd);
		kd->enabled = true;
		break;
	case KCOV_IOC_ENABLE_SUBMOD:
		//kd->submod = 1;
		// TODO: hack here we should handle modules in generic way
		// 	also this operation should be done before (kd->enabled)
		// 	other wise bad things can happen
		// 	if (kd->enabled)
		// 		return EBUSY;
		// 	mod_id = *((int *)addr);
		// 	kcov_submodule_enable(mod_id);
		if (kd->submod->enabled) {
			error = EBUSY;
			break;
		}
		if (kd->submod != NULL) {
// TODO: search list then connect submod	uid = *((uint64_t *)addr);
			kd->submod->enable_module(kd, kd->submod->ctx);
			// TODO: guard here via mutes similar to kcov way
			kd->submod->enabled = 1;
		} else {
			error = ENOENT;
		}
		break;
	case KCOV_IOC_DISABLE_SUBMOD:
		if (kd->submod != NULL) {
//			uid = *((uint64_t *)addr);
			kd->submod->enabled = 0;
			kd->submod->disable_module(kd, kd->submod->ctx);
		}
		break;
	// TODO: Here we also need to list modules
	case KCOV_IOC_DISABLE:
		if (!kd->enabled) {
			error = ENOENT;
			break;
		}
		if (lwp_getspecific(kcov_lwp_key) != kd) {
			error = ENOENT;
			break;
		}
		lwp_setspecific(kcov_lwp_key, NULL);
		kd->enabled = false;
		break;
	default:
		printf("#: MMPG : 2default#EINVAL\n");
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

	if ((size + off) > kd->bufsize) {
		error = ENOMEM;
		goto out;
	}

	uao_reference(kd->uobj);

	*uobjp = kd->uobj;
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
	uint64_t idx;
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

	if (kd->mode != KCOV_MODE_TRACE_PC) {
		/* PC tracing mode not enabled */
		return;
	}
	//TODO: it would be nice for perf to store buf, bufnent and afl_area
	//	inside current task, however it will require few changes.
	idx = kd->buf[0];
	if (__predict_true(idx < kd->bufnent)) {
		kd->buf[idx+1] =
		    (intptr_t)__builtin_return_address(0);
		kd->buf[0] = idx + 1;
		//TODO: Here we dont need as many checks just for API development
		if (kd->submod != NULL &&
		    kd->submod->enabled == 1 &&
		    kd->submod->supported_mode == KCOV_MODE_TRACE_PC &&
		    kd->submod->h_pctrace != NULL) {
			kd->submod->h_pctrace(kd->buf, idx, kd->submod->ctx);
		}
	}
}

static void
trace_cmp(uint64_t type, uint64_t arg1, uint64_t arg2, intptr_t pc)
{
	extern int cold;
	uint64_t idx;
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

	if (kd->mode != KCOV_MODE_TRACE_CMP) {
		/* CMP tracing mode not enabled */
		return;
	}

	idx = kd->buf[0];
	if ((idx * 4 + 4) <= kd->bufnent) {
		kd->buf[idx * 4 + 1] = type;
		kd->buf[idx * 4 + 2] = arg1;
		kd->buf[idx * 4 + 3] = arg2;
		kd->buf[idx * 4 + 4] = pc;
		kd->buf[0] = idx + 1;
	}
	if (kd->submod != NULL &&
	    kd->submod->enabled == 1 &&
	    kd->submod->supported_mode == KCOV_MODE_TRACE_CMP &&
	    kd->submod->h_cmptrace != NULL) {
		kd->submod->h_cmptrace(kd->buf, idx, type, arg1, arg2, pc,
						kd->submod->ctx);
	}
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

static void kafl_register(void);

static void
kcov_init(void)
{

	lwp_specific_key_create(&kcov_lwp_key, kcov_lwp_free);

	mutex_init(&modules_lock, MUTEX_DEFAULT, IPL_NONE);
	// Dirty hack for the while. Register AFL submodule
	kafl_register();
}

static void
kcov_deinit(void)
{
	// Dirty hack for the while. Un-register AFL submodule
	// kcov_unregister_submodule();
	// TODO: CLEAR all modules before that
	mutex_destroy(&modules_lock);
}

static int
kcov_modcmd(modcmd_t cmd, void *arg)
{

   	switch (cmd) {
	case MODULE_CMD_INIT:
		kcov_init();
		return 0;
	case MODULE_CMD_FINI:
		kcov_deinit();
		return EINVAL;
	default:
		return ENOTTY;
	}
}

/* -------------------------- COV SUBMODULES --------------------------- */
/* I would like to have it inside CPU hash, currently amd64 like */
/* Chuck Lever described efficiency of this technique:
 * http://www.citi.umich.edu/techreports/reports/citi-tr-00-1.pdf */
#define GOLDEN_RATIO_32 0x61C88647
#define GOLDEN_RATIO_64 0x61C8864680B583EBull
#define BITS_PER_LONG 	64

static uint64_t
_long_hash64(uint64_t val, unsigned int bits) {
	return val * GOLDEN_RATIO_64 >> (64 - bits);
}

static int cafl_open(dev_t dev, int flag, int mode, struct lwp *l);

dev_type_open(cafl_open);

static struct cdevsw cafl_cdevsw = {
	.d_open = cafl_open,
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

static int afl_fops_close(file_t *fp);

static int afl_fops_mmap(file_t *, off_t *, size_t, int, int *, int *,
			 struct uvm_object **, int *);

const struct fileops cafl_fileops = {
	.fo_read = fbadop_read,
	.fo_write = fbadop_write,
	.fo_ioctl = fbadop_ioctl,
	.fo_fcntl = fnullop_fcntl,
	.fo_poll = fnullop_poll,
	.fo_stat = fbadop_stat,
	.fo_close = afl_fops_close,
	.fo_kqfilter = fnullop_kqfilter,
	.fo_restart = fnullop_restart,
	.fo_mmap = afl_fops_mmap,
};

struct afl_softc {
	int enabled;
	int refcnt;
	kcov_int_t *afl_area;
	size_t afl_bsize;
	struct uvm_object *afl_uobj;
	uint64_t afl_prev_loc;
};

static struct afl_softc sc;

static const char * afl_mod_name = "afl_module";

static int kafl_enable_module(kcov_t *kd, void *kcov_ctx);
static int kafl_dissable_module(kcov_t *kd, void *kcov_ctx);
static void
kafl_handle_pctrace(kcov_int_t const *buf, uint64_t idx, void *kcov_ctx);

static int
kafl_unregister_module(struct kcov_module *mod)
{
	devsw_detach(NULL, &cafl_cdevsw);

	return 0;
}

// TODO: This assignment should be done inside kcov framework
static void
kafl_register(void)
{
	struct kcov_module *km;
	uint64_t uid;
	km = kmem_zalloc(sizeof(*km), KM_SLEEP);

	km->supported_mode = KCOV_MODE_TRACE_PC;
	km->mod_name = afl_mod_name;
	km->register_module = NULL;
	km->unregister_module = kafl_unregister_module;
	km->enable_module = &kafl_enable_module;
	km->disable_module = &kafl_dissable_module;
	km->h_cmptrace = NULL;
	km->h_pctrace = &kafl_handle_pctrace;
	km->ctx = &sc;

	kcov_register_module(km, &uid);

	int cmajor = 354, bmajor = -1;

	devsw_attach("afl", NULL, &bmajor, &cafl_cdevsw, &cmajor);

}

static void
kafl_handle_pctrace(kcov_int_t const *buf, uint64_t idx, void *kcov_ctx)
{
	struct afl_softc *asc = kcov_ctx;

	++asc->afl_area[(asc->afl_prev_loc ^ buf[idx]) & BITS_PER_LONG];
	asc->afl_prev_loc = _long_hash64(buf[idx], BITS_PER_LONG);
}

static int
kcov_realloc_aflbuf(struct afl_softc *as, size_t size)
{
	int error;

	if (as->afl_area != NULL) {
		uvm_deallocate(kernel_map, (vaddr_t)as->afl_area, as->afl_bsize);
	}

	as->afl_bsize = size;
	as->afl_uobj = uao_create(as->afl_bsize, 0);
	as->afl_area = NULL;

	error = uvm_map(kernel_map, (vaddr_t *)&as->afl_area, as->afl_bsize,
			as->afl_uobj, 0, 0, UVM_MAPFLAG(UVM_PROT_RW, UVM_PROT_RW,
			UVM_INH_SHARE, UVM_ADV_RANDOM, 0));
	if (error) {
		uao_detach(as->afl_uobj);
		return error;
	}
	error = uvm_map_pageable(kernel_map, (vaddr_t)as->afl_area,
	    (vaddr_t)as->afl_area + size, false, 0);

	if (error) {
		uvm_deallocate(kernel_map, (vaddr_t)as->afl_area, size);
		return error;
	}

	return 0;
}

static int
kcov_dealloc_aflbuf(struct afl_softc *as)
{
	uvm_deallocate(kernel_map, (vaddr_t)as->afl_area, KCOV_AFLBUF_SDEFAULT);

	uao_detach(as->afl_uobj);

	uvm_deallocate(kernel_map, (vaddr_t)as->afl_area, as->afl_bsize);

	return 0;
}

static int
kafl_enable_module(kcov_t *kd, void *kcov_ctx)
{
	struct afl_softc *as;
	int error;

	as = kcov_ctx;
	if (as == NULL)
		return -1;
	as->enabled = 1;
	as->afl_bsize = KCOV_AFLBUF_SDEFAULT;
	error = kcov_realloc_aflbuf(as, KCOV_AFLBUF_SDEFAULT);

	return error;
}

static int
kafl_dissable_module(kcov_t *kd, void *kcov_ctx)
{
	struct afl_softc *as;

	as = kcov_ctx;
	if (as == NULL)
		return -1;

	as->enabled = 0;
	kcov_dealloc_aflbuf(as);

	return 0;
}

static int
cafl_open(dev_t dev, int flag, int mode, struct lwp *l)
{
	struct file *fp;
	int error, fd;

	if (sc.refcnt > 0)
		return EBUSY;

	++sc.refcnt;

	error = fd_allocfile(&fp, &fd);
	if (error)
		return error;

	/** For later
	sc = kmem_zalloc(sizeof(*sc), KM_SLEEP);
	mutex_init(&sc->lock, MUTEX_DEFAULT, IPL_NONE);
	*/

	return fd_clone(fp, fd, flag, &cafl_fileops, &sc);
}

static int
afl_fops_close(file_t *fp)
{
	--sc.refcnt;

	fp->f_data = NULL;

   	return 0;
}

static int
afl_fops_mmap(file_t *fp, off_t *offp, size_t size, int prot, int *flagsp,
    int *advicep, struct uvm_object **uobjp, int *maxprotp)
{
	struct afl_softc *afls;
	off_t off = *offp;
	int error = 0;

	if (prot & PROT_EXEC)
		return EACCES;
	if (off < 0)
		return EINVAL;

	afls = fp->f_data;
	if (afls == NULL)
		return ENXIO;
	// TODO: Double check if it rather should be `off >= asd->afl_bsize`
	if (size > afls->afl_bsize || off > afls->afl_bsize )
		return EINVAL;

	// Do Locking kafl_lock(kd);

	if ((size + off) > afls->afl_bsize) {
		error = ENOMEM;
		goto out;
	}

	uao_reference(afls->afl_uobj);

	*uobjp = afls->afl_uobj;
	*maxprotp = prot;
	*advicep = UVM_ADV_RANDOM;

out:
	// TODO: locking kafl_unlock(kd);
	return error;
}

