/*	$NetBSD: vfs_trans.c,v 1.60 2019/05/13 08:16:56 hannken Exp $	*/

/*-
 * Copyright (c) 2007 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Juergen Hannken-Illjes.
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
__KERNEL_RCSID(0, "$NetBSD: vfs_trans.c,v 1.60 2019/05/13 08:16:56 hannken Exp $");

/*
 * File system transaction operations.
 */

#ifdef _KERNEL_OPT
#include "opt_ddb.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/atomic.h>
#include <sys/buf.h>
#include <sys/kmem.h>
#include <sys/mount.h>
#include <sys/pserialize.h>
#include <sys/vnode.h>
#include <sys/fstrans.h>
#include <sys/proc.h>

#include <miscfs/specfs/specdev.h>

enum fstrans_lock_type {
	FSTRANS_LAZY,			/* Granted while not suspended */
	FSTRANS_SHARED,			/* Granted while not suspending */
	FSTRANS_EXCL			/* Internal: exclusive lock */
};

struct fscow_handler {
	LIST_ENTRY(fscow_handler) ch_list;
	int (*ch_func)(void *, struct buf *, bool);
	void *ch_arg;
};
struct fstrans_lwp_info {
	struct fstrans_lwp_info *fli_succ;
	struct lwp *fli_self;
	struct mount *fli_mount;
	struct fstrans_lwp_info *fli_alias;
	struct fstrans_mount_info *fli_mountinfo;
	int fli_trans_cnt;
	int fli_alias_cnt;
	int fli_cow_cnt;
	enum fstrans_lock_type fli_lock_type;
	LIST_ENTRY(fstrans_lwp_info) fli_list;
};
struct fstrans_mount_info {
	enum fstrans_state fmi_state;
	unsigned int fmi_ref_cnt;
	bool fmi_gone;
	bool fmi_cow_change;
	LIST_HEAD(, fscow_handler) fmi_cow_handler;
	struct mount *fmi_mount;
};

static kmutex_t vfs_suspend_lock;	/* Serialize suspensions. */
static kmutex_t fstrans_lock;		/* Fstrans big lock. */
static kmutex_t fstrans_mount_lock;	/* Fstrans mount big lock. */
static kcondvar_t fstrans_state_cv;	/* Fstrans or cow state changed. */
static kcondvar_t fstrans_count_cv;	/* Fstrans or cow count changed. */
static pserialize_t fstrans_psz;	/* Pserialize state. */
static LIST_HEAD(fstrans_lwp_head, fstrans_lwp_info) fstrans_fli_head;
					/* List of all fstrans_lwp_info. */
static int fstrans_gone_count;		/* Number of fstrans_mount_info gone. */

static void fstrans_mount_dtor(struct fstrans_mount_info *);
static void fstrans_clear_lwp_info(void);
static inline struct fstrans_lwp_info *
    fstrans_get_lwp_info(struct mount *, bool);
static struct fstrans_lwp_info *fstrans_alloc_lwp_info(struct mount *);
static inline int _fstrans_start(struct mount *, enum fstrans_lock_type, int);
static bool grant_lock(const enum fstrans_state, const enum fstrans_lock_type);
static bool state_change_done(const struct fstrans_mount_info *);
static bool cow_state_change_done(const struct fstrans_mount_info *);
static void cow_change_enter(struct fstrans_mount_info *);
static void cow_change_done(struct fstrans_mount_info *);

extern struct mount *dead_rootmount;

#if defined(DIAGNOSTIC)

struct fstrans_debug_mount {
	struct mount *fdm_mount;
	SLIST_ENTRY(fstrans_debug_mount) fdm_list;
};

static SLIST_HEAD(, fstrans_debug_mount) fstrans_debug_mount_head =
    SLIST_HEAD_INITIALIZER(fstrans_debug_mount_head);

static void
fstrans_debug_mount(struct mount *mp)
{
	struct fstrans_debug_mount *fdm, *new;

	KASSERT(mutex_owned(&fstrans_mount_lock));

	mutex_exit(&fstrans_mount_lock);
	new = kmem_alloc(sizeof(*new), KM_SLEEP);
	new->fdm_mount = mp;
	mutex_enter(&fstrans_mount_lock);

	SLIST_FOREACH(fdm, &fstrans_debug_mount_head, fdm_list)
		KASSERT(fdm->fdm_mount != mp);
	SLIST_INSERT_HEAD(&fstrans_debug_mount_head, new, fdm_list);
}

static void
fstrans_debug_unmount(struct mount *mp)
{
	struct fstrans_debug_mount *fdm;

	KASSERT(mutex_owned(&fstrans_mount_lock));

	SLIST_FOREACH(fdm, &fstrans_debug_mount_head, fdm_list)
		if (fdm->fdm_mount == mp)
			break;
	KASSERT(fdm != NULL);
	SLIST_REMOVE(&fstrans_debug_mount_head, fdm,
	    fstrans_debug_mount, fdm_list);
	kmem_free(fdm, sizeof(*fdm));
}

static void
fstrans_debug_validate_mount(struct mount *mp)
{
	struct fstrans_debug_mount *fdm;

	KASSERT(mutex_owned(&fstrans_mount_lock));

	SLIST_FOREACH(fdm, &fstrans_debug_mount_head, fdm_list)
		if (fdm->fdm_mount == mp)
			break;
	KASSERTMSG(fdm != NULL, "mount %p invalid", mp);
}

#else /* defined(DIAGNOSTIC) */

#define fstrans_debug_mount(mp)
#define fstrans_debug_unmount(mp)
#define fstrans_debug_validate_mount(mp)

#endif  /* defined(DIAGNOSTIC) */

/*
 * Initialize.
 */
void
fstrans_init(void)
{

	mutex_init(&vfs_suspend_lock, MUTEX_DEFAULT, IPL_NONE);
	mutex_init(&fstrans_lock, MUTEX_DEFAULT, IPL_NONE);
	mutex_init(&fstrans_mount_lock, MUTEX_DEFAULT, IPL_NONE);
	cv_init(&fstrans_state_cv, "fstchg");
	cv_init(&fstrans_count_cv, "fstcnt");
	fstrans_psz = pserialize_create();
	LIST_INIT(&fstrans_fli_head);
}

/*
 * Deallocate lwp state.
 */
void
fstrans_lwp_dtor(lwp_t *l)
{
	struct fstrans_lwp_info *fli, *fli_next;

	for (fli = l->l_fstrans; fli; fli = fli_next) {
		KASSERT(fli->fli_trans_cnt == 0);
		KASSERT(fli->fli_cow_cnt == 0);
		KASSERT(fli->fli_self == l);
		if (fli->fli_mount != NULL)
			fstrans_mount_dtor(fli->fli_mountinfo);
		fli_next = fli->fli_succ;
		fli->fli_alias_cnt = 0;
		fli->fli_mount = NULL;
		fli->fli_alias = NULL;
		fli->fli_mountinfo = NULL;
		membar_sync();
		fli->fli_self = NULL;
	}

	l->l_fstrans = NULL;
}

/*
 * Dereference mount state.
 */
static void
fstrans_mount_dtor(struct fstrans_mount_info *fmi)
{

	mutex_enter(&fstrans_mount_lock);

	KASSERT(fmi != NULL);
	fmi->fmi_ref_cnt -= 1;
	if (fmi->fmi_ref_cnt > 0) {
		mutex_exit(&fstrans_mount_lock);
		return;
	}

	KASSERT(fmi->fmi_state == FSTRANS_NORMAL);
	KASSERT(LIST_FIRST(&fmi->fmi_cow_handler) == NULL);

	KASSERT(fstrans_gone_count > 0);
	fstrans_gone_count -= 1;

	mutex_exit(&fstrans_mount_lock);

	kmem_free(fmi->fmi_mount, sizeof(*fmi->fmi_mount));
	kmem_free(fmi, sizeof(*fmi));
}

/*
 * Allocate mount state.
 */
int
fstrans_mount(struct mount *mp)
{
	struct fstrans_mount_info *newfmi;

	newfmi = kmem_alloc(sizeof(*newfmi), KM_SLEEP);
	newfmi->fmi_state = FSTRANS_NORMAL;
	newfmi->fmi_ref_cnt = 1;
	newfmi->fmi_gone = false;
	LIST_INIT(&newfmi->fmi_cow_handler);
	newfmi->fmi_cow_change = false;
	newfmi->fmi_mount = mp;

	mutex_enter(&fstrans_mount_lock);
	mp->mnt_transinfo = newfmi;
	fstrans_debug_mount(mp);
	mutex_exit(&fstrans_mount_lock);

	return 0;
}

/*
 * Deallocate mount state.
 */
void
fstrans_unmount(struct mount *mp)
{
	struct fstrans_mount_info *fmi = mp->mnt_transinfo;

	KASSERT(fmi != NULL);

	mutex_enter(&fstrans_mount_lock);
	fstrans_debug_unmount(mp);
	fmi->fmi_gone = true;
	mp->mnt_transinfo = NULL;
	fstrans_gone_count += 1;
	mutex_exit(&fstrans_mount_lock);

	fstrans_mount_dtor(fmi);
}

/*
 * Clear mount entries whose mount is gone.
 */
static void
fstrans_clear_lwp_info(void)
{
	struct fstrans_lwp_info **p, *fli;

	/*
	 * Scan our list clearing entries whose mount is gone.
	 */
	for (p = &curlwp->l_fstrans; *p; ) {
		fli = *p;
		if (fli->fli_mount != NULL &&
		    fli->fli_mountinfo->fmi_gone &&
		    fli->fli_trans_cnt == 0 &&
		    fli->fli_cow_cnt == 0 &&
		    fli->fli_alias_cnt == 0) {
			*p = (*p)->fli_succ;
			fstrans_mount_dtor(fli->fli_mountinfo);
			if (fli->fli_alias) {
				KASSERT(fli->fli_alias->fli_alias_cnt > 0);
				fli->fli_alias->fli_alias_cnt--;
			}
			fli->fli_mount = NULL;
			fli->fli_alias = NULL;
			fli->fli_mountinfo = NULL;
			membar_sync();
			fli->fli_self = NULL;
			p = &curlwp->l_fstrans;
		} else {
			p = &(*p)->fli_succ;
		}
	}
#ifdef DIAGNOSTIC
	for (fli = curlwp->l_fstrans; fli; fli = fli->fli_succ)
		if (fli->fli_alias != NULL)
			KASSERT(fli->fli_alias->fli_self == curlwp);
#endif /* DIAGNOSTIC */
}

/*
 * Allocate and return per lwp info for this mount.
 */
static struct fstrans_lwp_info *
fstrans_alloc_lwp_info(struct mount *mp)
{
	struct fstrans_lwp_info *fli;
	struct fstrans_mount_info *fmi;

	for (fli = curlwp->l_fstrans; fli; fli = fli->fli_succ) {
		if (fli->fli_mount == mp)
			return fli;
	}

	/*
	 * Try to reuse a cleared entry or allocate a new one.
	 */
	mutex_enter(&fstrans_lock);
	LIST_FOREACH(fli, &fstrans_fli_head, fli_list) {
		membar_sync();
		if (fli->fli_self == NULL) {
			KASSERT(fli->fli_mount == NULL);
			KASSERT(fli->fli_trans_cnt == 0);
			KASSERT(fli->fli_cow_cnt == 0);
			KASSERT(fli->fli_alias_cnt == 0);
			fli->fli_self = curlwp;
			fli->fli_succ = curlwp->l_fstrans;
			curlwp->l_fstrans = fli;
			break;
		}
	}
	mutex_exit(&fstrans_lock);

	if (fli == NULL) {
		fli = kmem_alloc(sizeof(*fli), KM_SLEEP);
		mutex_enter(&fstrans_lock);
		memset(fli, 0, sizeof(*fli));
		fli->fli_self = curlwp;
		LIST_INSERT_HEAD(&fstrans_fli_head, fli, fli_list);
		mutex_exit(&fstrans_lock);
		fli->fli_succ = curlwp->l_fstrans;
		curlwp->l_fstrans = fli;
	}

	/*
	 * Attach the entry to the mount if its mnt_transinfo is valid.
	 */

	mutex_enter(&fstrans_mount_lock);
	fstrans_debug_validate_mount(mp);
	fmi = mp->mnt_transinfo;
	KASSERT(fmi != NULL);
	fli->fli_mount = mp;
	fli->fli_mountinfo = fmi;
	fmi->fmi_ref_cnt += 1;
	do {
		mp = mp->mnt_lower;
	} while (mp && mp->mnt_lower);
	mutex_exit(&fstrans_mount_lock);

	if (mp) {
		fli->fli_alias = fstrans_alloc_lwp_info(mp);
		fli->fli_alias->fli_alias_cnt++;
		fli = fli->fli_alias;
	}

	return fli;
}

/*
 * Retrieve the per lwp info for this mount allocating if necessary.
 */
static inline struct fstrans_lwp_info *
fstrans_get_lwp_info(struct mount *mp, bool do_alloc)
{
	struct fstrans_lwp_info *fli;

	/*
	 * Scan our list for a match.
	 */
	for (fli = curlwp->l_fstrans; fli; fli = fli->fli_succ) {
		if (fli->fli_mount == mp) {
			KASSERT((mp->mnt_lower == NULL) ==
			    (fli->fli_alias == NULL));
			if (fli->fli_alias != NULL)
				fli = fli->fli_alias;
			break;
		}
	}

	if (do_alloc) {
		if (__predict_false(fli == NULL))
			fli = fstrans_alloc_lwp_info(mp);
		KASSERT(fli != NULL && !fli->fli_mountinfo->fmi_gone);
	} else {
		KASSERT(fli != NULL);
	}

	return fli;
}

/*
 * Check if this lock type is granted at this state.
 */
static bool
grant_lock(const enum fstrans_state state, const enum fstrans_lock_type type)
{

	if (__predict_true(state == FSTRANS_NORMAL))
		return true;
	if (type == FSTRANS_EXCL)
		return true;
	if  (state == FSTRANS_SUSPENDING && type == FSTRANS_LAZY)
		return true;

	return false;
}

/*
 * Start a transaction.  If this thread already has a transaction on this
 * file system increment the reference counter.
 */
static inline int
_fstrans_start(struct mount *mp, enum fstrans_lock_type lock_type, int wait)
{
	int s;
	struct fstrans_lwp_info *fli;
	struct fstrans_mount_info *fmi;

#ifndef FSTRANS_DEAD_ENABLED
	if (mp == dead_rootmount)
		return 0;
#endif

	ASSERT_SLEEPABLE();

	fli = fstrans_get_lwp_info(mp, true);
	fmi = fli->fli_mountinfo;

	if (fli->fli_trans_cnt > 0) {
		KASSERT(lock_type != FSTRANS_EXCL);
		fli->fli_trans_cnt += 1;

		return 0;
	}

	s = pserialize_read_enter();
	if (__predict_true(grant_lock(fmi->fmi_state, lock_type))) {
		fli->fli_trans_cnt = 1;
		fli->fli_lock_type = lock_type;
		pserialize_read_exit(s);

		return 0;
	}
	pserialize_read_exit(s);

	if (! wait)
		return EBUSY;

	mutex_enter(&fstrans_lock);
	while (! grant_lock(fmi->fmi_state, lock_type))
		cv_wait(&fstrans_state_cv, &fstrans_lock);
	fli->fli_trans_cnt = 1;
	fli->fli_lock_type = lock_type;
	mutex_exit(&fstrans_lock);

	return 0;
}

void
fstrans_start(struct mount *mp)
{
	int error __diagused;

	error = _fstrans_start(mp, FSTRANS_SHARED, 1);
	KASSERT(error == 0);
}

int
fstrans_start_nowait(struct mount *mp)
{

	return _fstrans_start(mp, FSTRANS_SHARED, 0);
}

void
fstrans_start_lazy(struct mount *mp)
{
	int error __diagused;

	error = _fstrans_start(mp, FSTRANS_LAZY, 1);
	KASSERT(error == 0);
}

/*
 * Finish a transaction.
 */
void
fstrans_done(struct mount *mp)
{
	int s;
	struct fstrans_lwp_info *fli;
	struct fstrans_mount_info *fmi;

#ifndef FSTRANS_DEAD_ENABLED
	if (mp == dead_rootmount)
		return;
#endif

	fli = fstrans_get_lwp_info(mp, false);
	fmi = fli->fli_mountinfo;
	KASSERT(fli->fli_trans_cnt > 0);

	if (fli->fli_trans_cnt > 1) {
		fli->fli_trans_cnt -= 1;

		return;
	}

	if (__predict_false(fstrans_gone_count > 0))
		fstrans_clear_lwp_info();

	s = pserialize_read_enter();
	if (__predict_true(fmi->fmi_state == FSTRANS_NORMAL)) {
		fli->fli_trans_cnt = 0;
		pserialize_read_exit(s);

		return;
	}
	pserialize_read_exit(s);

	mutex_enter(&fstrans_lock);
	fli->fli_trans_cnt = 0;
	cv_signal(&fstrans_count_cv);
	mutex_exit(&fstrans_lock);
}

/*
 * Check if this thread has an exclusive lock.
 */
int
fstrans_is_owner(struct mount *mp)
{
	struct fstrans_lwp_info *fli;

	KASSERT(mp != dead_rootmount);

	fli = fstrans_get_lwp_info(mp, true);

	if (fli->fli_trans_cnt == 0)
		return 0;

	return (fli->fli_lock_type == FSTRANS_EXCL);
}

/*
 * True, if no thread is in a transaction not granted at the current state.
 */
static bool
state_change_done(const struct fstrans_mount_info *fmi)
{
	struct fstrans_lwp_info *fli;

	KASSERT(mutex_owned(&fstrans_lock));

	LIST_FOREACH(fli, &fstrans_fli_head, fli_list) {
		if (fli->fli_mountinfo != fmi)
			continue;
		if (fli->fli_trans_cnt == 0)
			continue;
		if (grant_lock(fmi->fmi_state, fli->fli_lock_type))
			continue;

		return false;
	}

	return true;
}

/*
 * Set new file system state.
 */
int
fstrans_setstate(struct mount *mp, enum fstrans_state new_state)
{
	int error;
	enum fstrans_state old_state;
	struct fstrans_lwp_info *fli;
	struct fstrans_mount_info *fmi;

	KASSERT(mp != dead_rootmount);

	fli = fstrans_get_lwp_info(mp, true);
	fmi = fli->fli_mountinfo;
	old_state = fmi->fmi_state;
	if (old_state == new_state)
		return 0;

	mutex_enter(&fstrans_lock);
	fmi->fmi_state = new_state;
	pserialize_perform(fstrans_psz);

	/*
	 * All threads see the new state now.
	 * Wait for transactions invalid at this state to leave.
	 */
	error = 0;
	while (! state_change_done(fmi)) {
		error = cv_wait_sig(&fstrans_count_cv, &fstrans_lock);
		if (error) {
			new_state = fmi->fmi_state = FSTRANS_NORMAL;
			break;
		}
	}
	cv_broadcast(&fstrans_state_cv);
	mutex_exit(&fstrans_lock);

	if (old_state != new_state) {
		if (old_state == FSTRANS_NORMAL)
			_fstrans_start(mp, FSTRANS_EXCL, 1);
		if (new_state == FSTRANS_NORMAL)
			fstrans_done(mp);
	}

	return error;
}

/*
 * Get current file system state.
 */
enum fstrans_state
fstrans_getstate(struct mount *mp)
{
	struct fstrans_lwp_info *fli;
	struct fstrans_mount_info *fmi;

	KASSERT(mp != dead_rootmount);

	fli = fstrans_get_lwp_info(mp, true);
	fmi = fli->fli_mountinfo;

	return fmi->fmi_state;
}

/*
 * Request a filesystem to suspend all operations.
 */
int
vfs_suspend(struct mount *mp, int nowait)
{
	struct fstrans_lwp_info *fli;
	int error;

	if (mp == dead_rootmount)
		return EOPNOTSUPP;

	fli = fstrans_get_lwp_info(mp, true);
	mp = fli->fli_mount;

	if (nowait) {
		if (!mutex_tryenter(&vfs_suspend_lock))
			return EWOULDBLOCK;
	} else
		mutex_enter(&vfs_suspend_lock);

	if ((error = VFS_SUSPENDCTL(mp, SUSPEND_SUSPEND)) != 0)
		mutex_exit(&vfs_suspend_lock);

	return error;
}

/*
 * Request a filesystem to resume all operations.
 */
void
vfs_resume(struct mount *mp)
{
	struct fstrans_lwp_info *fli;

	KASSERT(mp != dead_rootmount);

	fli = fstrans_get_lwp_info(mp, false);
	mp = fli->fli_mount;

	VFS_SUSPENDCTL(mp, SUSPEND_RESUME);
	mutex_exit(&vfs_suspend_lock);
}


/*
 * True, if no thread is running a cow handler.
 */
static bool
cow_state_change_done(const struct fstrans_mount_info *fmi)
{
	struct fstrans_lwp_info *fli;

	KASSERT(mutex_owned(&fstrans_lock));
	KASSERT(fmi->fmi_cow_change);

	LIST_FOREACH(fli, &fstrans_fli_head, fli_list) {
		if (fli->fli_mount != fmi->fmi_mount)
			continue;
		if (fli->fli_cow_cnt == 0)
			continue;

		return false;
	}

	return true;
}

/*
 * Prepare for changing this mounts cow list.
 * Returns with fstrans_lock locked.
 */
static void
cow_change_enter(struct fstrans_mount_info *fmi)
{

	mutex_enter(&fstrans_lock);

	/*
	 * Wait for other threads changing the list.
	 */
	while (fmi->fmi_cow_change)
		cv_wait(&fstrans_state_cv, &fstrans_lock);

	/*
	 * Wait until all threads are aware of a state change.
	 */
	fmi->fmi_cow_change = true;
	pserialize_perform(fstrans_psz);

	while (! cow_state_change_done(fmi))
		cv_wait(&fstrans_count_cv, &fstrans_lock);
}

/*
 * Done changing this mounts cow list.
 */
static void
cow_change_done(struct fstrans_mount_info *fmi)
{

	KASSERT(mutex_owned(&fstrans_lock));

	fmi->fmi_cow_change = false;
	pserialize_perform(fstrans_psz);

	cv_broadcast(&fstrans_state_cv);

	mutex_exit(&fstrans_lock);
}

/*
 * Add a handler to this mount.
 */
int
fscow_establish(struct mount *mp, int (*func)(void *, struct buf *, bool),
    void *arg)
{
	struct fstrans_mount_info *fmi;
	struct fscow_handler *newch;

	KASSERT(mp != dead_rootmount);

	mutex_enter(&fstrans_mount_lock);
	fmi = mp->mnt_transinfo;
	KASSERT(fmi != NULL);
	fmi->fmi_ref_cnt += 1;
	mutex_exit(&fstrans_mount_lock);

	newch = kmem_alloc(sizeof(*newch), KM_SLEEP);
	newch->ch_func = func;
	newch->ch_arg = arg;

	cow_change_enter(fmi);
	LIST_INSERT_HEAD(&fmi->fmi_cow_handler, newch, ch_list);
	cow_change_done(fmi);

	return 0;
}

/*
 * Remove a handler from this mount.
 */
int
fscow_disestablish(struct mount *mp, int (*func)(void *, struct buf *, bool),
    void *arg)
{
	struct fstrans_mount_info *fmi;
	struct fscow_handler *hp = NULL;

	KASSERT(mp != dead_rootmount);

	fmi = mp->mnt_transinfo;
	KASSERT(fmi != NULL);

	cow_change_enter(fmi);
	LIST_FOREACH(hp, &fmi->fmi_cow_handler, ch_list)
		if (hp->ch_func == func && hp->ch_arg == arg)
			break;
	if (hp != NULL) {
		LIST_REMOVE(hp, ch_list);
		kmem_free(hp, sizeof(*hp));
	}
	cow_change_done(fmi);

	fstrans_mount_dtor(fmi);

	return hp ? 0 : EINVAL;
}

/*
 * Check for need to copy block that is about to be written.
 */
int
fscow_run(struct buf *bp, bool data_valid)
{
	int error, s;
	struct mount *mp;
	struct fstrans_lwp_info *fli;
	struct fstrans_mount_info *fmi;
	struct fscow_handler *hp;

	/*
	 * First check if we need run the copy-on-write handler.
	 */
	if ((bp->b_flags & B_COWDONE))
		return 0;
	if (bp->b_vp == NULL) {
		bp->b_flags |= B_COWDONE;
		return 0;
	}
	if (bp->b_vp->v_type == VBLK)
		mp = spec_node_getmountedfs(bp->b_vp);
	else
		mp = bp->b_vp->v_mount;
	if (mp == NULL || mp == dead_rootmount) {
		bp->b_flags |= B_COWDONE;
		return 0;
	}

	fli = fstrans_get_lwp_info(mp, true);
	fmi = fli->fli_mountinfo;

	/*
	 * On non-recursed run check if other threads
	 * want to change the list.
	 */
	if (fli->fli_cow_cnt == 0) {
		s = pserialize_read_enter();
		if (__predict_false(fmi->fmi_cow_change)) {
			pserialize_read_exit(s);
			mutex_enter(&fstrans_lock);
			while (fmi->fmi_cow_change)
				cv_wait(&fstrans_state_cv, &fstrans_lock);
			fli->fli_cow_cnt = 1;
			mutex_exit(&fstrans_lock);
		} else {
			fli->fli_cow_cnt = 1;
			pserialize_read_exit(s);
		}
	} else
		fli->fli_cow_cnt += 1;

	/*
	 * Run all copy-on-write handlers, stop on error.
	 */
	error = 0;
	LIST_FOREACH(hp, &fmi->fmi_cow_handler, ch_list)
		if ((error = (*hp->ch_func)(hp->ch_arg, bp, data_valid)) != 0)
			break;
 	if (error == 0)
 		bp->b_flags |= B_COWDONE;

	/*
	 * Check if other threads want to change the list.
	 */
	if (fli->fli_cow_cnt > 1) {
		fli->fli_cow_cnt -= 1;
	} else {
		s = pserialize_read_enter();
		if (__predict_false(fmi->fmi_cow_change)) {
			pserialize_read_exit(s);
			mutex_enter(&fstrans_lock);
			fli->fli_cow_cnt = 0;
			cv_signal(&fstrans_count_cv);
			mutex_exit(&fstrans_lock);
		} else {
			fli->fli_cow_cnt = 0;
			pserialize_read_exit(s);
		}
	}

	return error;
}

#if defined(DDB)
void fstrans_dump(int);

static void
fstrans_print_lwp(struct proc *p, struct lwp *l, int verbose)
{
	char prefix[9];
	struct fstrans_lwp_info *fli;

	snprintf(prefix, sizeof(prefix), "%d.%d", p->p_pid, l->l_lid);
	LIST_FOREACH(fli, &fstrans_fli_head, fli_list) {
		if (fli->fli_self != l)
			continue;
		if (fli->fli_trans_cnt == 0 && fli->fli_cow_cnt == 0) {
			if (! verbose)
				continue;
		}
		printf("%-8s", prefix);
		if (verbose)
			printf(" @%p", fli);
		if (fli->fli_mount == dead_rootmount)
			printf(" <dead>");
		else if (fli->fli_mount != NULL)
			printf(" (%s)", fli->fli_mount->mnt_stat.f_mntonname);
		else
			printf(" NULL");
		if (fli->fli_alias != NULL) {
			struct mount *amp = fli->fli_alias->fli_mount;

			printf(" alias");
			if (verbose)
				printf(" @%p", fli->fli_alias);
			if (amp == NULL)
				printf(" NULL");
			else
				printf(" (%s)", amp->mnt_stat.f_mntonname);
		}
		if (fli->fli_mountinfo && fli->fli_mountinfo->fmi_gone)
			printf(" gone");
		if (fli->fli_trans_cnt == 0) {
			printf(" -");
		} else {
			switch (fli->fli_lock_type) {
			case FSTRANS_LAZY:
				printf(" lazy");
				break;
			case FSTRANS_SHARED:
				printf(" shared");
				break;
			case FSTRANS_EXCL:
				printf(" excl");
				break;
			default:
				printf(" %#x", fli->fli_lock_type);
				break;
			}
		}
		printf(" %d cow %d alias %d\n",
		    fli->fli_trans_cnt, fli->fli_cow_cnt, fli->fli_alias_cnt);
		prefix[0] = '\0';
	}
}

static void
fstrans_print_mount(struct mount *mp, int verbose)
{
	struct fstrans_mount_info *fmi;

	fmi = mp->mnt_transinfo;
	if (!verbose && (fmi == NULL || fmi->fmi_state == FSTRANS_NORMAL))
		return;

	printf("%-16s ", mp->mnt_stat.f_mntonname);
	if (fmi == NULL) {
		printf("(null)\n");
		return;
	}
	switch (fmi->fmi_state) {
	case FSTRANS_NORMAL:
		printf("state normal\n");
		break;
	case FSTRANS_SUSPENDING:
		printf("state suspending\n");
		break;
	case FSTRANS_SUSPENDED:
		printf("state suspended\n");
		break;
	default:
		printf("state %#x\n", fmi->fmi_state);
		break;
	}
}

void
fstrans_dump(int full)
{
	const struct proclist_desc *pd;
	struct proc *p;
	struct lwp *l;
	struct mount *mp;

	printf("Fstrans locks by lwp:\n");
	for (pd = proclists; pd->pd_list != NULL; pd++)
		PROCLIST_FOREACH(p, pd->pd_list)
			LIST_FOREACH(l, &p->p_lwps, l_sibling)
				fstrans_print_lwp(p, l, full == 1);

	printf("Fstrans state by mount:\n");
	for (mp = _mountlist_next(NULL); mp; mp = _mountlist_next(mp))
		fstrans_print_mount(mp, full == 1);
}
#endif /* defined(DDB) */
