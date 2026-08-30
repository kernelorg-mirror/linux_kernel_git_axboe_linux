// SPDX-License-Identifier: GPL-2.0
/*
 * Inline issue handoff: if an inline issue blocks, the submitter's identity
 * moves to an idle io-wq worker which returns to userspace as the submitter,
 * while the submitter finishes the request as the worker.
 *
 * Copyright (C) 2026 Jens Axboe
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/sched/task_stack.h>
#include <linux/signal.h>
#include <linux/task_work.h>
#include <linux/thread_handoff.h>
#include <linux/io_uring.h>
#include <linux/blkdev.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <asm/syscall.h>

#include "io_uring.h"
#include "io-wq.h"
#include "opdef.h"
#include "tctx.h"
#include "handoff.h"

int sysctl_io_uring_handoff __read_mostly = 1;

static long io_handoff_resume(void);

/*
 * Can @req be issued inline in blocking mode with a handoff ready. Everything
 * but the spare worker check is static, REQ_F_HANDOFF caches that part.
 */
bool io_handoff_possible(struct io_kiocb *req)
{
	const struct io_issue_def *def = &io_issue_defs[req->opcode];
	struct io_ring_ctx *ctx = req->ctx;
	struct io_uring_task *tctx = current->io_uring;

	if (!sysctl_io_uring_handoff)
		return false;
	if (req->flags & REQ_F_HANDOFF)
		goto check_spare;
	if (!def->blockable)
		return false;
	/* nonblocking semantics were asked for, -EAGAIN is the answer */
	if (req->flags & REQ_F_NOWAIT)
		return false;
	/* IOPOLL/SQPOLL issue differently, SQ_REWIND can't resume mid-batch */
	if (ctx->flags & (IORING_SETUP_IOPOLL | IORING_SETUP_SQPOLL |
			  IORING_SETUP_SQ_REWIND))
		return false;
	/* pollable files keep the nonblocking issue + poll retry path */
	if (io_file_can_poll(req))
		return false;
	/* FMODE_NOWAIT files have a working nonblocking path, keep using it */
	if ((def->pollin || def->pollout) && req->file &&
	    (req->file->f_mode & FMODE_NOWAIT))
		return false;
	if (!tctx->io_wq)
		return false;
	/* an intermediate task's own user state doesn't matter, it stays */
	if (!tctx->handoff.src && !thread_handoff_allowed(current))
		return false;
	/* the SQ head is published while we may still be running */
	if (io_req_sqe_copy(req, IO_URING_F_INLINE))
		return false;
	req->flags |= REQ_F_HANDOFF;
check_spare:
	/* have a worker ready to take over */
	if (!io_wq_handoff_spare(tctx->io_wq, !io_req_unbound(req), false))
		return false;
	return true;
}

/* fork a spare worker upfront, so the first blockable issue has a target */
void io_handoff_prime(struct io_uring_task *tctx, struct io_ring_ctx *ctx)
{
	if (!sysctl_io_uring_handoff || !tctx->io_wq)
		return;
	/* handoffs are never done for these, see io_handoff_possible() */
	if (ctx->flags & (IORING_SETUP_IOPOLL | IORING_SETUP_SQPOLL |
			  IORING_SETUP_SQ_REWIND))
		return;
	io_wq_handoff_spare(tctx->io_wq, true, true);
}

/*
 * Blocking inline issues run with an io-wq worker's signal mask, a request
 * shouldn't fail with -EINTR because the submitter has a timer.
 */
static void io_handoff_block_signals(struct io_handoff *ho)
{
	sigset_t mask;

	if (ho->sigsaved)
		return;
	ho->sigsaved = true;
	ho->sigmask = current->blocked;
	siginitsetinv(&mask, sigmask(SIGKILL) | sigmask(SIGSTOP));
	set_current_blocked(&mask);
}

void __io_handoff_restore_signals(struct io_handoff *ho)
{
	ho->sigsaved = false;
	set_current_blocked(&ho->sigmask);
}

/*
 * Arm a handoff for the inline issue of @req. Until io_handoff_end() the issue
 * runs like on io-wq, neither normal signals nor task_work interrupt it.
 */
bool __io_handoff_begin(struct io_kiocb *req)
{
	struct io_handoff *ho = &current->io_uring->handoff;

	if (!io_handoff_possible(req))
		return false;
	/* would interrupt the issue right away, and can't be handled here */
	if (task_sigpending(current))
		return false;

	ho->req = req;
	io_handoff_block_signals(ho);
	current->flags |= PF_IO_HANDOFF;
	/* already queued task_work gets picked up by io_handoff_end() too */
	if (test_thread_flag(TIF_NOTIFY_SIGNAL))
		clear_notify_signal();
	return true;
}

/* Returns true if the identity got handed off during the issue */
bool io_handoff_end(void)
{
	bool handed_off = current->flags & PF_IO_WORKER;

	current->flags &= ~PF_IO_HANDOFF;
	/* pairs with io_wq_task_work_add(), notify for work queued meanwhile */
	smp_mb();
	if (task_work_pending(current))
		set_notify_signal(current);

	/* once handed off the tctx isn't ours anymore */
	if (likely(!handed_off))
		current->io_uring->handoff.req = NULL;
	return handed_off;
}

/* close our part of the batch and drop uring_lock for the promoted task */
static void io_handoff_release_ring(struct io_ring_ctx *ctx,
				    struct io_handoff *ho)
	__releases(&ctx->uring_lock)
{
	lockdep_assert_held(&ctx->uring_lock);

	ho->consumed += io_submit_sqes_abandon(ctx);
	mutex_unlock(&ctx->uring_lock);
}

/* move the outstanding tctx task refs from @src to @dst, see io_put_task() */
static void io_handoff_task_refs(struct io_uring_task *tctx,
				 struct task_struct *src,
				 struct task_struct *dst)
{
	unsigned int nr;

	raw_spin_lock(&tctx->task_ref_lock);
	nr = percpu_counter_sum(&tctx->inflight);
	refcount_add(nr, &dst->usage);
	WRITE_ONCE(tctx->task, dst);
	raw_spin_unlock(&tctx->task_ref_lock);

	/* dropped by the promoted task */
	tctx->handoff.prev_refs = nr;
}

/* move tctx task_work queued on @task along to the tctx's new task */
void io_handoff_tw_moved(struct io_uring_task *tctx, struct task_struct *task)
{
	struct task_struct *cur;

	while (task_work_cancel(task, &tctx->task_work)) {
		cur = READ_ONCE(tctx->task);
		if (WARN_ON_ONCE(task_work_add(cur, &tctx->task_work, TWA_SIGNAL)))
			break;
		if (READ_ONCE(tctx->task) == cur)
			break;
		task = cur;
	}
}

/* Move the io_uring task state from @src to @dst */
static void io_handoff_move_tctx(struct io_uring_task *tctx,
				 struct task_struct *src,
				 struct task_struct *dst)
{
	struct io_tctx_node *node;

	io_handoff_task_refs(tctx, src, dst);

	dst->io_uring = tctx;
	src->io_uring = NULL;
	dst->io_uring_restrict = src->io_uring_restrict;
	src->io_uring_restrict = NULL;

	list_for_each_entry(node, &tctx->node_list, tctx_link) {
		struct io_ring_ctx *ctx = node->ctx;

		node->task = dst;
		if (READ_ONCE(ctx->submitter_task) == src) {
			get_task_struct(dst);
			WRITE_ONCE(ctx->submitter_task, dst);
			put_task_struct(src);
		}
	}

	io_handoff_tw_moved(tctx, src);
}

/*
 * Called from sched_submit_work() when a task blocks inside an inline issue,
 * hand our identity to an idle worker. Can't block, uring_lock is held.
 */
void io_uring_task_sleeping(struct task_struct *tsk)
{
	struct io_uring_task *tctx = tsk->io_uring;
	struct io_handoff *ho = &tctx->handoff;
	struct io_kiocb *req = ho->req;
	struct io_ring_ctx *ctx = req->ctx;
	/* the identity being handed around, ours unless we're intermediate */
	struct task_struct *src = ho->src ?: tsk;
	struct task_struct *dst;
	bool bound;

	WARN_ON_ONCE(tsk != current);

	/* the issue path is touching state that needs the ring lock held */
	if (ctx->submit_lock_depth)
		return;
	if (src == tsk && !thread_handoff_prepare(tsk))
		return;

	/* don't let the woken worker preempt us before we've committed */
	preempt_disable();
	bound = !io_req_unbound(req);
	dst = io_wq_handoff_claim(tctx->io_wq, bound, io_handoff_resume, src);
	if (!dst) {
		preempt_enable();
		return;
	}

	/* committed, @req is ours as the worker from here on */
	ho->src = src;
	ho->prev = tsk;
	ho->ctx = ctx;
	ho->bound = bound;
	/* our accounting follows the identity, an intermediate's doesn't */
	if (src == tsk)
		thread_handoff_stats_take(&ho->stats);

	io_handoff_release_ring(ctx, ho);
	io_handoff_move_tctx(tctx, tsk, dst);
	io_wq_handoff_commit(dst);

	/* do what sched_submit_work() would have done for an io-wq worker */
	io_wq_worker_sleeping(tsk);
	preempt_enable();
}

/* the issue of @req blocked and we're a worker now, finish it like io-wq */
int io_handoff_complete(struct io_kiocb *req, int ret)
{
	WARN_ON_ONCE(!io_wq_current_is_worker());

	if (ret == IOU_COMPLETE) {
		req->io_task_work.func = io_req_task_complete;
		io_req_task_work_add(req);
	} else if (ret == IOU_ISSUE_SKIP_COMPLETE) {
		/* completes on its own */
	} else if ((ret == -EAGAIN && !(req->flags & REQ_F_NOWAIT)) ||
		   io_issue_wants_restart(ret)) {
		/* wants a blocking retry, or got interrupted, io-wq does that */
		io_queue_iowq(req);
	} else {
		io_req_task_queue_fail(req, ret);
	}

	return -EIOCBQUEUED;
}

/*
 * Runs on the promoted task, finishes io_uring_enter() for the submitter. Only
 * takes its identity if it gets through the submission without handing off.
 */
static long io_handoff_resume(void)
{
	struct io_uring_task *tctx = current->io_uring;
	struct io_handoff *ho = &tctx->handoff;
	struct task_struct *src = ho->src, *prev = ho->prev;
	struct io_ring_ctx *ctx = ho->ctx;
	bool bound = ho->bound;
	long ret;

	/* enough of the identity to issue requests on its behalf */
	thread_handoff_adopt_creds(src);
	put_task_struct_many(prev, ho->prev_refs);
	ho->prev_refs = 0;
	ho->prev = NULL;
	ho->req = NULL;
	ho->ctx = NULL;
	/* an intermediate task has nothing we still need, let it work */
	if (prev != src)
		io_wq_handoff_finished(prev);

	/* flush what the blocked batch left behind, then submit the rest */
	io_run_task_work();
	mutex_lock(&ctx->uring_lock);
	io_submit_flush_completions(ctx);
	if (ho->consumed < ho->to_submit) {
		ret = io_submit_sqes(ctx, ho->to_submit - ho->consumed);
		if (ret == -EIOCBQUEUED)
			return ret;
		if (ret > 0)
			ho->consumed += ret;
	}

	mutex_unlock(&ctx->uring_lock);

	/* submission done, become the submitter and return to userspace */
	if (WARN_ON_ONCE(thread_handoff_finish(src, &ho->stats)))
		force_sig(SIGKILL);
	if (ho->sigsaved)
		__io_handoff_restore_signals(ho);
	io_wq_handoff_finished(src);
	ho->src = NULL;

	ret = ho->consumed;
	if (ret == ho->to_submit && (ho->flags & IORING_ENTER_GETEVENTS)) {
		mutex_lock(&ctx->uring_lock);
		ret = io_uring_enter_finish(ctx, ret, ho->min_complete,
					    ho->flags, ho->argp, ho->argsz);
	}
	if (!(ho->flags & IORING_ENTER_REGISTERED_RING))
		fput(ho->file);

	/* we took a worker, top the spare pool back up now the work is done */
	io_wq_handoff_spare(tctx->io_wq, bound, true);

	syscall_set_return_value(current, task_pt_regs(current),
				 ret < 0 ? ret : 0, ret);
	return ret;
}

/* run the worker loop after a demotion, returns once handed an identity */
long io_uring_handoff_worker(void)
{
	io_wq_handoff_fn *fn;
	long ret;

	do {
		fn = io_wq_handoff_worker();
		ret = fn();
	} while (ret == -EIOCBQUEUED);

	return ret;
}
