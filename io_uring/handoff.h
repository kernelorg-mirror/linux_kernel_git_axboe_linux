/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IOU_HANDOFF_H
#define IOU_HANDOFF_H

#include <linux/io_uring_types.h>
#include "opdef.h"
#include "tw.h"

/* sysctl io_uring_handoff */
#define IO_URING_HANDOFF_OFF		0
#define IO_URING_HANDOFF_IDENTITY	1	/* blocked issue hands off its identity */
#define IO_URING_HANDOFF_SYNC		2	/* an idle worker issues, we wait */

#ifdef CONFIG_THREAD_HANDOFF
extern int sysctl_io_uring_handoff;

bool io_handoff_possible(struct io_kiocb *req);
bool __io_handoff_begin(struct io_kiocb *req);
void io_handoff_prime(struct io_uring_task *tctx, struct io_ring_ctx *ctx);
bool io_handoff_end(void);
void __io_handoff_restore_signals(struct io_handoff *ho);
int io_handoff_complete(struct io_kiocb *req, int ret);
long io_uring_handoff_worker(void);
void io_handoff_tw_moved(struct io_uring_task *tctx, struct task_struct *task);

/*
 * Stash the io_uring_enter() arguments so a promoted task can resume it, and
 * run pending task_work so it doesn't interrupt a blocking issue later.
 */
static inline void io_handoff_enter(struct file *file, u32 to_submit,
				    u32 min_complete, u32 flags,
				    const void __user *argp, size_t argsz)
{
	struct io_handoff *ho = &current->io_uring->handoff;

	io_run_task_work();
	ho->file = file;
	ho->to_submit = to_submit;
	ho->consumed = 0;
	ho->min_complete = min_complete;
	ho->flags = flags;
	ho->argp = argp;
	ho->argsz = argsz;
}

/*
 * Done issuing, restore the signal mask if we changed it. Not with a handoff
 * in flight, io_handoff_resume() does that once it has the identity.
 */
static inline void io_handoff_submit_end(void)
{
	struct io_handoff *ho = &current->io_uring->handoff;

	if (unlikely(ho->sigsaved) && !ho->src)
		__io_handoff_restore_signals(ho);
}

/* if true, @req gets a blocking inline issue. Pair with io_handoff_end() */
static inline bool io_handoff_begin(struct io_kiocb *req,
				    const struct io_issue_def *def,
				    unsigned int issue_flags)
{
	if (!(issue_flags & IO_URING_F_INLINE) || !def->blockable)
		return false;
	return __io_handoff_begin(req);
}

/* if true, @req should go to an idle worker synchronously instead */
static inline bool io_handoff_sync_wanted(struct io_kiocb *req,
					  const struct io_issue_def *def,
					  unsigned int issue_flags)
{
	if (sysctl_io_uring_handoff != IO_URING_HANDOFF_SYNC)
		return false;
	if (!(issue_flags & IO_URING_F_INLINE) || !def->blockable)
		return false;
	return io_handoff_possible(req);
}
#else
static inline void io_handoff_enter(struct file *file, u32 to_submit,
				    u32 min_complete, u32 flags,
				    const void __user *argp, size_t argsz)
{
}
static inline bool io_handoff_begin(struct io_kiocb *req,
				    const struct io_issue_def *def,
				    unsigned int issue_flags)
{
	return false;
}
static inline bool io_handoff_possible(struct io_kiocb *req)
{
	return false;
}
static inline bool io_handoff_sync_wanted(struct io_kiocb *req,
					  const struct io_issue_def *def,
					  unsigned int issue_flags)
{
	return false;
}
static inline void io_handoff_submit_end(void)
{
}
static inline bool io_handoff_end(void)
{
	return false;
}
static inline int io_handoff_complete(struct io_kiocb *req, int ret)
{
	return -EFAULT;
}
static inline long io_uring_handoff_worker(void)
{
	return -EFAULT;
}
static inline void io_handoff_tw_moved(struct io_uring_task *tctx,
				       struct task_struct *task)
{
}
static inline void io_handoff_prime(struct io_uring_task *tctx,
				    struct io_ring_ctx *ctx)
{
}
#endif

#endif
