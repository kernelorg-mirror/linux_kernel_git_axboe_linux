/* SPDX-License-Identifier: GPL-2.0 */
#include "io_uring.h"
#include "wait.h"
#include "loop.h"
#include "tctx.h"

static inline int io_loop_nr_cqes(const struct io_ring_ctx *ctx,
				  const struct iou_loop_params *lp)
{
	return lp->cq_wait_idx - READ_ONCE(ctx->rings->cq.tail);
}

static inline void io_loop_wait_finish(struct io_ring_ctx *ctx)
{
	__set_current_state(TASK_RUNNING);
	atomic_set(&ctx->cq_wait_nr, IO_CQ_WAKE_INIT);
}

static void io_loop_wait(struct io_ring_ctx *ctx, struct iou_loop_params *lp,
			 unsigned nr_wait,
			 struct io_ring_ctx_lock_state *lock_state)
{
	io_cq_wait_arm(ctx, nr_wait);

	if (unlikely(io_local_work_pending(ctx) ||
		     io_loop_nr_cqes(ctx, lp) <= 0) ||
		     READ_ONCE(ctx->check_cq)) {
		io_loop_wait_finish(ctx);
		return;
	}

	io_ring_ctx_unlock(ctx, lock_state);
	schedule();
	io_loop_wait_finish(ctx);
	io_ring_ctx_lock(ctx, lock_state);
}

static int __io_run_loop(struct io_ring_ctx *ctx,
			 struct io_ring_ctx_lock_state *lock_state)
{
	struct iou_loop_params lp = {};

	while (true) {
		int nr_wait, step_res;

		if (unlikely(!ctx->loop_step))
			return -EFAULT;

		step_res = ctx->loop_step(io_loop_mangle_ctx(ctx), &lp);
		if (step_res == IOU_LOOP_STOP)
			break;
		if (step_res != IOU_LOOP_CONTINUE)
			return -EINVAL;

		nr_wait = io_loop_nr_cqes(ctx, &lp);
		if (nr_wait > 0)
			io_loop_wait(ctx, &lp, nr_wait, lock_state);
		else
			nr_wait = 0;

		if (task_work_pending(current)) {
			io_ring_ctx_unlock(ctx, lock_state);
			io_run_task_work();
			io_ring_ctx_lock(ctx, lock_state);
		}
		if (unlikely(task_sigpending(current)))
			return -EINTR;
		io_run_local_work_locked(ctx, nr_wait);

		if (READ_ONCE(ctx->check_cq) & BIT(IO_CHECK_CQ_OVERFLOW_BIT))
			io_cqring_overflow_flush_locked(ctx, lock_state);
	}

	return 0;
}

int io_run_loop(struct io_ring_ctx *ctx)
{
	struct io_ring_ctx_lock_state lock_state;
	int ret;

	ret = io_uring_add_tctx_node(ctx);
	if (unlikely(ret))
		return ret;

	if (!io_allowed_run_tw(ctx))
		return -EEXIST;

	io_ring_ctx_lock(ctx, &lock_state);
	ret = __io_run_loop(ctx, &lock_state);
	io_ring_ctx_unlock(ctx, &lock_state);
	return ret;
}
