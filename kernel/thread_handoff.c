// SPDX-License-Identifier: GPL-2.0
/*
 * Thread identity handoff, see include/linux/thread_handoff.h
 *
 * Copyright (C) 2026 Jens Axboe
 */
#include <linux/thread_handoff.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/sched/rt.h>
#include <linux/sched/mm.h>
#include <linux/audit.h>
#include <linux/cgroup.h>
#include <linux/cred.h>
#include <linux/futex.h>
#include <linux/mempolicy.h>
#include <linux/pid.h>
#include <linux/rseq.h>
#include <linux/seccomp.h>
#include <linux/thread_info.h>
#include <uapi/linux/sched/types.h>
#include <linux/ioprio.h>
#include <linux/iocontext.h>
#include <linux/task_io_accounting_ops.h>

/* PR_MCE_KILL and PR_SET_IO_FLUSHER state */
#define THREAD_HANDOFF_PF_FLAGS	(PF_MCE_PROCESS | PF_MCE_EARLY | \
				 PF_MEMALLOC_NOIO | PF_LOCAL_THROTTLE)

/*
 * Check if the identity of @tsk (must be current) can be handed off at
 * all. Not meant to be complete, meant to be safe.
 */
bool thread_handoff_allowed(struct task_struct *tsk)
{
	WARN_ON_ONCE(tsk != current);

	if (tsk->flags & (PF_EXITING | PF_KTHREAD | PF_IO_WORKER))
		return false;
	if (tsk->ptrace)
		return false;
	/* tracees point back at the tracer task */
	if (!list_empty(&tsk->ptraced))
		return false;
	if (tsk->signal->flags & SIGNAL_GROUP_EXIT)
		return false;
#ifdef CONFIG_PERF_EVENTS
	/* per-task perf contexts are bound to the task_struct */
	if (tsk->perf_event_ctxp)
		return false;
#endif
#ifdef CONFIG_FUTEX
	/* PI futex ownership is tied to the task_struct */
	if (!list_empty(&tsk->futex.pi_state_list))
		return false;
#endif
#ifdef CONFIG_GENERIC_ENTRY
	if (test_syscall_work(SYSCALL_USER_DISPATCH))
		return false;
#endif
	/* only the fair class moves, see thread_handoff_sched() */
	if (rt_or_dl_task(tsk))
		return false;
#ifdef CONFIG_SCHED_CORE
	/* the core scheduling cookie is bound to the task */
	if (tsk->core_cookie)
		return false;
#endif
#ifdef CONFIG_KCOV
	/* coverage collection is per-thread */
	if (tsk->kcov)
		return false;
#endif
#ifdef CONFIG_POSIX_TIMERS
	/* armed per-thread CPU timers would sample the destination's clock */
	if (tsk->posix_cputimers.timers_active)
		return false;
#endif
	/* the syscall never exits, its audit record would never be emitted */
	if (!audit_dummy_context())
		return false;

	return arch_thread_handoff_allowed(tsk);
}

/*
 * Check if @dst can take over the identity of @src. Callable from
 * sched_submit_work() context.
 */
bool thread_handoff_compatible(struct task_struct *src, struct task_struct *dst)
{
	if (dst->flags & PF_EXITING)
		return false;
	if (dst->ptrace)
		return false;
	if (!same_thread_group(src, dst))
		return false;
#ifdef CONFIG_GENERIC_ENTRY
	/* inherited from the thread that forked the destination */
	if (test_task_syscall_work(dst, SYSCALL_USER_DISPATCH))
		return false;
#endif
	if (dst->mm != src->mm || dst->files != src->files ||
	    dst->fs != src->fs || dst->nsproxy != src->nsproxy)
		return false;
	/* the identity must not gain no_new_privs */
	if (task_no_new_privs(dst) && !task_no_new_privs(src))
		return false;
#ifdef CONFIG_SECCOMP
	/* seccomp filters are per-thread, the identity must not escape them */
	if (dst->seccomp.mode != src->seccomp.mode ||
	    dst->seccomp.filter != src->seccomp.filter)
		return false;
#endif
	return arch_thread_handoff_allowed(dst);
}

/*
 * Runs on the source right before it blocks: sync live user register state
 * into the task struct, nothing else ever will.
 */
bool thread_handoff_prepare(struct task_struct *tsk)
{
	WARN_ON_ONCE(tsk != current);
	/* may have gotten traced since thread_handoff_allowed() was checked */
	if (tsk->ptrace)
		return false;
	return arch_thread_handoff_prepare();
}

/*
 * Runs on the source once it's committed to the handoff, still as current:
 * take its accumulated per-thread accounting for the destination, so the
 * counters userspace sees for the tid don't go backwards. Only the task
 * itself ever writes these, the tick does so from irq context on this CPU.
 * The source starts over, like the io-wq worker it becomes.
 */
void thread_handoff_stats_take(struct thread_handoff_stats *st)
{
	struct task_struct *p = current;

	st->exec_runtime = sched_exec_runtime_take(p);

	local_irq_disable();
	st->utime = p->utime;
	st->stime = p->stime;
	st->gtime = p->gtime;
	p->utime = p->stime = p->gtime = 0;
#ifndef CONFIG_VIRT_CPU_ACCOUNTING_NATIVE
	raw_spin_lock(&p->prev_cputime.lock);
	p->prev_cputime.utime = p->prev_cputime.stime = 0;
	raw_spin_unlock(&p->prev_cputime.lock);
#endif
	local_irq_enable();

	st->min_flt = p->min_flt;
	st->maj_flt = p->maj_flt;
	st->nvcsw = p->nvcsw;
	st->nivcsw = p->nivcsw;
	p->min_flt = p->maj_flt = p->nvcsw = p->nivcsw = 0;
	st->ioac = p->ioac;
	memset(&p->ioac, 0, sizeof(p->ioac));
}

static void thread_handoff_stats_add(struct task_struct *p,
				     struct thread_handoff_stats *st)
{
	sched_exec_runtime_add(p, st->exec_runtime);

	local_irq_disable();
	p->utime += st->utime;
	p->stime += st->stime;
	p->gtime += st->gtime;
	local_irq_enable();

	p->min_flt += st->min_flt;
	p->maj_flt += st->maj_flt;
	p->nvcsw += st->nvcsw;
	p->nivcsw += st->nivcsw;
	task_io_accounting_add(&p->ioac, &st->ioac);
}

/*
 * The blocked mask, altstack and thread-private pending signals follow the
 * identity. The source gets a kernel worker's mask, only fatal signals and
 * SIGSTOP get through.
 */
static void thread_handoff_signals(struct task_struct *dst,
				   struct task_struct *src)
	__must_hold(&dst->sighand->siglock)
{
	dst->blocked = src->blocked;
	dst->real_blocked = src->real_blocked;
	dst->saved_sigmask = src->saved_sigmask;
	dst->sas_ss_sp = src->sas_ss_sp;
	dst->sas_ss_size = src->sas_ss_size;
	dst->sas_ss_flags = src->sas_ss_flags;
	dst->restart_block = src->restart_block;

	siginitsetinv(&src->blocked, sigmask(SIGKILL) | sigmask(SIGSTOP));
	sigemptyset(&src->real_blocked);
	sas_ss_reset(src);

	list_splice_tail_init(&src->pending.list, &dst->pending.list);
	sigorsets(&dst->pending.signal, &dst->pending.signal,
		  &src->pending.signal);
	sigemptyset(&src->pending.signal);
}

/*
 * The leader's tid is the tgid and what the parent waits on, so
 * leadership follows the identity. Similar to what de_thread() does at exec.
 * The old leader lives on as a regular thread.
 */
static void thread_handoff_leader(struct task_struct *dst,
				  struct task_struct *src)
	__must_hold(&tasklist_lock)
{
	struct task_struct *t;

	transfer_pid(src, dst, PIDTYPE_TGID);
	transfer_pid(src, dst, PIDTYPE_PGID);
	transfer_pid(src, dst, PIDTYPE_SID);

	list_replace_rcu(&src->tasks, &dst->tasks);
	list_replace_init(&src->sibling, &dst->sibling);

	for_each_thread(dst, t)
		t->group_leader = dst;

	dst->exit_signal = src->exit_signal;
	src->exit_signal = -1;
}

/*
 * Children are parented to the thread that forked them, and they get their
 * pdeath_signal when that task exits. Move them along with the identity.
 */
static void thread_handoff_children(struct task_struct *dst,
				    struct task_struct *src)
	__must_hold(&tasklist_lock)
{
	struct task_struct *p;

	list_for_each_entry(p, &src->children, sibling) {
		RCU_INIT_POINTER(p->real_parent, dst);
		if (rcu_access_pointer(p->parent) == src)
			RCU_INIT_POINTER(p->parent, dst);
	}
	list_splice_init(&src->children, &dst->children);
	dst->self_exec_id = src->self_exec_id;
}

static bool thread_handoff_sched_same(struct task_struct *dst,
				      struct task_struct *src)
{
	if (dst->policy != src->policy || task_nice(dst) != task_nice(src))
		return false;
	if (dst->sched_reset_on_fork != src->sched_reset_on_fork)
		return false;
	if (dst->se.custom_slice != src->se.custom_slice ||
	    (src->se.custom_slice && dst->se.slice != src->se.slice))
		return false;
#ifdef CONFIG_UCLAMP_TASK
	for (int i = 0; i < UCLAMP_CNT; i++) {
		if (dst->uclamp_req[i].user_defined != src->uclamp_req[i].user_defined)
			return false;
		if (src->uclamp_req[i].user_defined &&
		    dst->uclamp_req[i].value != src->uclamp_req[i].value)
			return false;
	}
#endif
	return true;
}

/*
 * Policy, nice, per-task uclamp and reset-on-fork follow the identity. The
 * common case is that nothing differs, and sched_setattr() isn't cheap.
 */
static void thread_handoff_sched(struct task_struct *dst,
				 struct task_struct *src)
{
	struct sched_attr attr = {
		.sched_policy = src->policy,
		.sched_nice = task_nice(src),
	};

	if (thread_handoff_sched_same(dst, src))
		return;
	if (src->sched_reset_on_fork)
		attr.sched_flags |= SCHED_FLAG_RESET_ON_FORK;
	if (src->se.custom_slice)
		attr.sched_runtime = src->se.slice;
#ifdef CONFIG_UCLAMP_TASK
	if (src->uclamp_req[UCLAMP_MIN].user_defined) {
		attr.sched_flags |= SCHED_FLAG_UTIL_CLAMP_MIN;
		attr.sched_util_min = src->uclamp_req[UCLAMP_MIN].value;
	}
	if (src->uclamp_req[UCLAMP_MAX].user_defined) {
		attr.sched_flags |= SCHED_FLAG_UTIL_CLAMP_MAX;
		attr.sched_util_max = src->uclamp_req[UCLAMP_MAX].value;
	}
#endif
	WARN_ON_ONCE(sched_setattr_nocheck(dst, &attr));
}

static void thread_handoff_mempolicy(struct task_struct *dst,
				     struct task_struct *src)
{
#ifdef CONFIG_NUMA
	struct mempolicy *pol = mpol_dup(src->mempolicy);

	if (IS_ERR(pol))
		return;
	task_lock(dst);
	swap(dst->mempolicy, pol);
	task_unlock(dst);
	mpol_put(pol);
#endif
}

#ifdef CONFIG_BLOCK
/* an ionice'd thread keeps its IO priority; the ioc itself stays put */
static void thread_handoff_ioprio(struct task_struct *dst,
				  struct task_struct *src)
{
	struct io_context *ioc = src->io_context;

	/* workers share the ioc of the thread that forked them, detach */
	if (dst->io_context)
		exit_io_context(dst);
	if (ioc && ioprio_valid(ioc->ioprio))
		WARN_ON_ONCE(set_task_ioprio(dst, ioc->ioprio));
}
#else
static void thread_handoff_ioprio(struct task_struct *dst,
				  struct task_struct *src)
{
}
#endif

#ifdef CONFIG_CGROUPS
/*
 * A thread may have been placed in a threaded cgroup by its TID, that
 * placement follows the identity. The source stays where it is, the
 * request it is finishing is owned by that cgroup anyway.
 */
static void thread_handoff_cgroup(struct task_struct *dst,
				  struct task_struct *src)
{
	if (rcu_access_pointer(src->cgroups) == rcu_access_pointer(dst->cgroups))
		return;
	WARN_ON_ONCE(cgroup_attach_task_all(src, dst));
}
#else
static void thread_handoff_cgroup(struct task_struct *dst,
				  struct task_struct *src)
{
}
#endif

/*
 * Runs on the destination, in process context. The source may still be running
 * kernel code, but it never returns to userspace and never looks at the state
 * moved here.
 */
int thread_handoff_finish(struct task_struct *src,
			  struct thread_handoff_stats *st)
{
	struct task_struct *dst = current;
	struct sighand_struct *sighand = dst->sighand;
	char comm[TASK_COMM_LEN];
	bool leader;

	WARN_ON_ONCE(sighand != src->sighand);

	/* tid, leadership, and signal state swap in one go */
	cgroup_threadgroup_change_begin(dst);
	write_lock_irq(&tasklist_lock);
	spin_lock(&sighand->siglock);
	leader = thread_group_leader(src);
	exchange_tids(dst, src);
	if (leader)
		thread_handoff_leader(dst, src);
	thread_handoff_children(dst, src);
	thread_handoff_signals(dst, src);
	spin_unlock(&sighand->siglock);
	write_unlock_irq(&tasklist_lock);
	cgroup_threadgroup_change_end(dst);
	recalc_sigpending();

#ifdef CONFIG_FUTEX
	dst->futex.robust_list = src->futex.robust_list;
	src->futex.robust_list = NULL;
#ifdef CONFIG_COMPAT
	dst->futex.compat_robust_list = src->futex.compat_robust_list;
	src->futex.compat_robust_list = NULL;
#endif
#endif
	dst->clear_child_tid = src->clear_child_tid;
	src->clear_child_tid = NULL;

#ifdef CONFIG_RSEQ
	scoped_guard(irqsave) {
		dst->rseq = src->rseq;
		memset(&src->rseq, 0, sizeof(src->rseq));
		src->rseq.ids.cpu_id = RSEQ_CPU_ID_UNINITIALIZED;
	}
	rseq_force_update();
#endif

	/* creds can differ per thread if setuid() and friends were used */
	if (dst->real_cred != src->real_cred)
		commit_creds((struct cred *)get_cred(src->real_cred));

	dst->personality = src->personality;
	dst->pdeath_signal = src->pdeath_signal;
	dst->timer_slack_ns = src->timer_slack_ns;
	dst->default_timer_slack_ns = src->default_timer_slack_ns;
	dst->start_time = src->start_time;
	dst->start_boottime = src->start_boottime;
	if (task_no_new_privs(src))
		task_set_no_new_privs(dst);
	/* prctl driven per-task flags, the source keeps them for its work */
	dst->flags = (dst->flags & ~THREAD_HANDOFF_PF_FLAGS) |
		     (src->flags & THREAD_HANDOFF_PF_FLAGS);

	thread_handoff_mempolicy(dst, src);
	thread_handoff_cgroup(dst, src);
	thread_handoff_ioprio(dst, src);
	thread_handoff_stats_add(dst, st);

	thread_handoff_sched(dst, src);
	dup_user_cpus_ptr(dst, src, NUMA_NO_NODE);
	set_cpus_allowed_ptr(dst, src->cpus_ptr);

	get_task_comm(comm, src);
	set_task_comm(dst, comm);

	return arch_thread_handoff_finish(src);
}
