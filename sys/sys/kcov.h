/*      $NetBSD: kcov.h,v 1.6 2019/05/26 01:44:34 kamil Exp $        */

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

#ifndef _SYS_KCOV_H_
#define _SYS_KCOV_H_

#include <sys/param.h>
#include <sys/types.h>
#include <sys/atomic.h>

#define KCOV_IOC_SETBUFSIZE	_IOW('K', 1, uint64_t)
#define KCOV_IOC_ENABLE		_IOW('K', 2, int)
#define KCOV_IOC_DISABLE	_IO('K', 3)
#define KCOV_IOC_ENABLE_SUBMOD	_IOW('K', 4, uint64_t)
#define KCOV_IOC_DISABLE_SUBMOD	_IOW('K', 5, uint64_t)

#define KCOV_MODE_NONE		0
#define KCOV_MODE_TRACE_PC	1
#define KCOV_MODE_TRACE_CMP	2

typedef volatile uint64_t kcov_int_t;
#define KCOV_ENTRY_SIZE sizeof(kcov_int_t)

typedef struct kcov_desc kcov_t;

/* KCOV API for submodules */
typedef struct kcov_module {
	/* Describe what tracing mode is supported via module */
	int supported_mode;
	/* Module Name */
	const char * mod_name;
	/* Module ID (md5 from name) */
	uint64_t mod_id;
	/* If submodule is enabled? */
	int enabled;
	/* Any additional actions that needs to be done before enablining the mod */
	int (*register_module) (struct kcov_module *);
	/* Cleanup after registration */
	int (*unregister_module) (struct kcov_module *);
	/* After enabling the module the handler for trace can be run anytime */
	int (*enable_module) (kcov_t *kd, void *kcov_ctx);
	/* After Disabling module trace handlers wont be called anymore */
	int (*disable_module) (kcov_t *kd, void *kcov_ctx);
	/* Handlers for tracing */
	// TODO: wrap type,arg1,arg2,pc into structure
	void (*h_cmptrace) (kcov_int_t const *buf, uint64_t idx, uint64_t type,
			  uint64_t arg1, uint64_t arg2, intptr_t pc, void *ctx);
	void (*h_pctrace) (kcov_int_t const *buf, uint64_t idx, void *ctx);
	/* Module private data */
	void *ctx;
} kcov_module_t;

/* Register kcov module */
int kcov_register_module(kcov_module_t *mod, uint64_t *id);

/* Unregister kcov module */
int kcov_unregister_module(uint64_t id);

#endif /* !_SYS_KCOV_H_ */
