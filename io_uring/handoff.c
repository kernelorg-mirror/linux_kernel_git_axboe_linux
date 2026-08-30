// SPDX-License-Identifier: GPL-2.0
/*
 * Inline issue handoff: requests that may block are issued inline anyway,
 * and if the issue blocks, the user identity of the submitter is handed
 * to an idle io-wq worker. The worker returns to userspace as the
 * submitter, the submitter finishes the request as the worker.
 *
 * Copyright (C) 2026 Jens Axboe
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/sched/task_stack.h>
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
 * Check if @req can be issued inline in blocking mode with a handoff
 * ready for if it blocks. If not, the request falls back to the classic
 * nonblocking issue + io-wq punt.
 */
bool io_handoff_possible(struct io_kiocb *req)
{
	const struct io_issue_def *def = &io_issue_defs[req->opcode];
	struct io_ring_ctx *ctx = req->ctx;
	struct io_uring_task *tctx = current->io_uring;

	if (!sysctl_io_uring_handoff)
		return false;
	if (!def->blockable)
		return false;
	/* nonblocking semantics were asked for, -EAGAIN is the answer */
	if (req->flags & REQ_F_NOWAIT)
		return false;
	if (ctx->flags & (IORING_SETUP_IOPOLL | IORING_SETUP_SQPOLL))
		return false;
	/* pollable files keep the nonblocking issue + poll retry path */
	if (io_file_can_poll(req))
		return false;
	/*
	 * Reads and writes on a file with FMODE_NOWAIT have a working
	 * nonblocking path (inline completion, IOCB_WAITQ retry, or a
	 * punt); a blocking issue with an identity swap per op would be
	 * worse. Handoff is for requests whose only alternative is an
	 * up-front punt.
	 */
	if ((def->pollin || def->pollout) && req->file &&
	    (req->file->f_mode & FMODE_NOWAIT))
		return false;
	if (!tctx->io_wq)
		return false;
	if (!thread_handoff_allowed(current))
		return false;
	/* the SQ head is published while we may still be running */
	if (io_req_sqe_copy(req, IO_URING_F_INLINE))
		return false;
	/* have a worker ready to take over */
	return io_wq_handoff_spare(tctx->io_wq, !io_req_unbound(req), false);
}

/* Mark the task for a handoff if the inline issue of @req blocks */
bool __io_handoff_begin(struct io_kiocb *req)
{
	if (!io_handoff_possible(req))
		return false;

	current->io_uring->handoff.req = req;
	current->flags |= PF_IO_HANDOFF;
	return true;
}

/*
 * Fork a spare worker when a task starts using a ring, so the first
 * blockable issue has a handoff target. It exits with the wq once the
 * last ring is gone.
 */
void io_handoff_prime(struct io_uring_task *tctx, struct io_ring_ctx *ctx)
{
	if (!sysctl_io_uring_handoff || !tctx->io_wq)
		return;
	/* handoffs are never done for these, see io_handoff_possible() */
	if (ctx->flags & (IORING_SETUP_IOPOLL | IORING_SETUP_SQPOLL))
		return;
	io_wq_handoff_spare(tctx->io_wq, true, true);
}

/* Returns true if the identity got handed off during the issue */
bool io_handoff_end(void)
{
	bool handed_off = current->flags & PF_IO_WORKER;

	current->flags &= ~PF_IO_HANDOFF;
	if (likely(!handed_off))
		current->io_uring->handoff.req = NULL;
	return handed_off;
}

/*
 * Drop the uring_lock for the promoted task. The plug stays with us: it
 * lives on our stack and the block layer may reference it across the
 * sleep. The promoted task starts its own.
 */
static void io_handoff_release_ring(struct io_ring_ctx *ctx)
	__releases(&ctx->uring_lock)
{
	lockdep_assert_held(&ctx->uring_lock);

	ctx->submit_state.plug_started = false;
	mutex_unlock(&ctx->uring_lock);
}

/*
 * Move the outstanding tctx task references from @src to @dst. Off-task
 * puts serialize against the switch via ->task_ref_lock, see
 * io_put_task().
 */
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

	/* dropped by the promoted task once it's done taking over */
	tctx->handoff.src_refs = nr;
}

/*
 * Move tctx task_work queued on @task along to the tctx's new task, the
 * old one may take a long time to run it, or never will.
 */
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
 * Called from sched_submit_work() when a task blocks inside an inline
 * issue: hand our identity to an idle worker, which resumes the syscall,
 * while we finish the request and become the worker. Can't block here,
 * and uring_lock is still held.
 */
void io_uring_task_sleeping(struct task_struct *tsk)
{
	struct io_uring_task *tctx = tsk->io_uring;
	struct io_handoff *ho = &tctx->handoff;
	struct io_kiocb *req = ho->req;
	struct io_ring_ctx *ctx = req->ctx;
	struct task_struct *dst;

	WARN_ON_ONCE(tsk != current);

	/* the issue path is touching state that needs the ring lock held */
	if (ctx->submit_lock_depth)
		return;
	if (!thread_handoff_prepare(tsk))
		return;

	/*
	 * Should the woken worker land on this CPU, keep it from running
	 * until we've committed, or it just goes back to sleep waiting.
	 */
	preempt_disable();
	dst = io_wq_handoff_claim(tctx->io_wq, !io_req_unbound(req),
				  io_handoff_resume);
	if (!dst) {
		preempt_enable();
		return;
	}

	/* committed - PF_IO_HANDOFF stays set until the issue returns */
	ho->src = tsk;
	thread_handoff_stats_take(&ho->stats);

	io_handoff_release_ring(ctx);
	io_handoff_move_tctx(tctx, tsk, dst);
	io_wq_handoff_commit(dst);

	/* do what sched_submit_work() would have done for an io-wq worker */
	io_wq_worker_sleeping(tsk);
	preempt_enable();
}

/*
 * The issue of @req blocked and our identity is gone. Deal with the
 * result like io-wq would, completions routed via task_work to the task
 * that owns the ring now.
 */
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
 * Runs on the task that got handed the submitter identity: finish taking
 * it over, then resume io_uring_enter() where io_submit_sqes() would have
 * returned and take the syscall result to userspace.
 */
static long io_handoff_resume(void)
{
	struct io_uring_task *tctx = current->io_uring;
	struct io_handoff *ho = &tctx->handoff;
	struct task_struct *src = ho->src;
	struct io_kiocb *req = ho->req;
	struct io_ring_ctx *ctx = req->ctx;
	struct io_submit_state *state = &ctx->submit_state;
	bool bound = !io_req_unbound(req);
	unsigned int consumed, left;
	long ret;

	if (WARN_ON_ONCE(thread_handoff_finish(src, &ho->stats)))
		force_sig(SIGKILL);
	io_wq_handoff_finished(src);
	put_task_struct_many(src, ho->src_refs);
	ho->src_refs = 0;
	ho->src = NULL;
	ho->req = NULL;

	/* we took a worker, top the spare pool back up */
	io_wq_handoff_spare(tctx->io_wq, bound, true);

	/*
	 * Finish the batch the blocked request was part of, then submit
	 * what's left of the syscall. Another handoff continues from here,
	 * the consumed count lives in the tctx.
	 */
	io_run_task_work();
	mutex_lock(&ctx->uring_lock);
	consumed = ctx->cached_sq_head - state->sq_head;
	left = state->submit_nr - consumed;
	ret = io_submit_sqes_end(ctx, state->submit_nr, left);
	ho->consumed += ret;
	if (ho->consumed < ho->to_submit) {
		ret = io_submit_sqes(ctx, ho->to_submit - ho->consumed);
		if (ret == -EIOCBQUEUED)
			return ret;
		if (ret > 0)
			ho->consumed += ret;
	}
	ret = ho->consumed;
	if (ret != ho->to_submit) {
		mutex_unlock(&ctx->uring_lock);
	} else {
		ret = io_uring_enter_finish(ctx, ret, ho->min_complete,
					    ho->flags, ho->argp, ho->argsz);
	}
	if (!(ho->flags & IORING_ENTER_REGISTERED_RING))
		fput(ho->file);

	syscall_set_return_value(current, task_pt_regs(current),
				 ret < 0 ? ret : 0, ret);
	return ret;
}

/*
 * Run the worker loop after a demotion. Only returns if we get handed an
 * identity again, with that syscall's result.
 */
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
