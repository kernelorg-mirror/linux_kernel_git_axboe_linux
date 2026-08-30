/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IOU_HANDOFF_H
#define IOU_HANDOFF_H

#include <linux/io_uring_types.h>
#include "opdef.h"
#include "tw.h"

/* a blocking issue got interrupted, retry on io-wq rather than restart */
static inline bool io_issue_wants_restart(int ret)
{
	return ret == -ERESTARTSYS || ret == -ERESTARTNOINTR ||
	       ret == -ERESTARTNOHAND || ret == -ERESTART_RESTARTBLOCK;
}

#ifdef CONFIG_THREAD_HANDOFF
extern int sysctl_io_uring_handoff;

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

/* a submit call is done issuing, restore the signal mask if we changed it */
static inline void io_handoff_submit_end(void)
{
	struct io_handoff *ho = &current->io_uring->handoff;

	if (unlikely(ho->sigsaved))
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
