/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_THREAD_HANDOFF_H
#define _LINUX_THREAD_HANDOFF_H

#include <linux/sched.h>

/* per-thread accounting that follows the identity */
struct thread_handoff_stats {
	u64				utime;
	u64				stime;
	u64				gtime;
	u64				exec_runtime;
	unsigned long			min_flt;
	unsigned long			maj_flt;
	unsigned long			nvcsw;
	unsigned long			nivcsw;
	struct task_io_accounting	ioac;
};

/*
 * Move the user visible identity of a thread that is about to block in the
 * kernel (tid, signals, registers, rseq, creds, sched attributes, ...) to
 * another thread in the same group, which then returns to userspace on its
 * behalf. The blocked thread keeps its task_struct and in-kernel state.
 */
#ifdef CONFIG_THREAD_HANDOFF
bool thread_handoff_allowed(struct task_struct *tsk);
bool thread_handoff_compatible(struct task_struct *src,
			       struct task_struct *dst);
bool thread_handoff_prepare(struct task_struct *tsk);
void thread_handoff_stats_take(struct thread_handoff_stats *st);
void thread_handoff_adopt_creds(struct task_struct *src);
int thread_handoff_finish(struct task_struct *src,
			  struct thread_handoff_stats *st);

u64 sched_exec_runtime_take(struct task_struct *p);
void sched_exec_runtime_add(struct task_struct *p, u64 ns);

/*
 * Arch hooks. _prepare() syncs the live user register state on the source
 * before it blocks, _finish() copies it over and loads what the return to
 * userspace won't. @leader tells it that thread group leadership moved.
 */
bool arch_thread_handoff_allowed(struct task_struct *tsk);
bool arch_thread_handoff_compatible(struct task_struct *src,
				    struct task_struct *dst);
bool arch_thread_handoff_prepare(void);
int arch_thread_handoff_finish(struct task_struct *src, bool leader);
#else
static inline bool thread_handoff_allowed(struct task_struct *tsk)
{
	return false;
}
static inline bool thread_handoff_compatible(struct task_struct *src,
					     struct task_struct *dst)
{
	return false;
}
static inline bool thread_handoff_prepare(struct task_struct *tsk)
{
	return false;
}
static inline void thread_handoff_stats_take(struct thread_handoff_stats *st)
{
}
static inline void thread_handoff_adopt_creds(struct task_struct *src)
{
}
static inline int thread_handoff_finish(struct task_struct *src,
					struct thread_handoff_stats *st)
{
	return -EOPNOTSUPP;
}
#endif

#endif
