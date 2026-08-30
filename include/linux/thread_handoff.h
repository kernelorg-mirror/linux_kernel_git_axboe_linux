/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_THREAD_HANDOFF_H
#define _LINUX_THREAD_HANDOFF_H

#include <linux/sched.h>

/*
 * Per-thread accounting that follows the identity, so that the counters
 * userspace sees for a tid stay monotonic across a handoff.
 */
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
 * Thread identity handoff: move the user visible identity of a thread that is
 * about to block in the kernel to another thread in the same group, which then
 * returns to userspace on its behalf while the blocked thread finishes the
 * work. The blocking thread keeps its task_struct, kernel stack and all
 * in-kernel state. Only what userspace observes moves to the receiver ("dst").
 * This includes tid, signal state, registers, rseq/robust list, scheduling
 * attributes, etc.
 *
 * The source checks thread_handoff_allowed() and _compatible(), and calls
 * thread_handoff_prepare() right before blocking (sched_submit_work() context,
 * must not block), then thread_handoff_stats_take() once it's committed to
 * the handoff. The receiver calls thread_handoff_finish() with those stats
 * and must not return to userspace before it completes.
 */
#ifdef CONFIG_THREAD_HANDOFF
bool thread_handoff_allowed(struct task_struct *tsk);
bool thread_handoff_compatible(struct task_struct *src,
			       struct task_struct *dst);
bool thread_handoff_prepare(struct task_struct *tsk);
void thread_handoff_stats_take(struct thread_handoff_stats *st);
int thread_handoff_finish(struct task_struct *src,
			  struct thread_handoff_stats *st);

u64 sched_exec_runtime_take(struct task_struct *p);
void sched_exec_runtime_add(struct task_struct *p, u64 ns);

/*
 * arch_thread_handoff_allowed() checks that a task can take part in a
 * handoff, on either side. arch_thread_handoff_prepare() syncs live user
 * register state on the source before it blocks, arch_thread_handoff_finish()
 * copies it to the destination and loads what the return to userspace
 * doesn't load.
 */
bool arch_thread_handoff_allowed(struct task_struct *tsk);
bool arch_thread_handoff_prepare(void);
int arch_thread_handoff_finish(struct task_struct *src);
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
static inline int thread_handoff_finish(struct task_struct *src,
					struct thread_handoff_stats *st)
{
	return -EOPNOTSUPP;
}
#endif

#endif
