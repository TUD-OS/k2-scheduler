// SPDX-License-Identifier: GPL-2.0
/*
 * K2 - A prototype of a work-constraining I/O scheduler
 *
 * Copyright (c) 2019 Till Miemietz
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/bio.h>
#include <linux/blk-mq.h>
#include <linux/ioprio.h>

/*
 * blk_mq_sched_request_inserted() is EXPORT_SYMBOL_GPL'ed, but it is declared
 * in the header file block/blk-mq-sched.h, which is not part of the installed
 * kernel headers a module is built against (only part of the full source).
 * Therefore, we forward-declare it again here.
 * (implicitly declared functions are an error.)
 */
extern void blk_mq_sched_request_inserted(struct request *rq);

/* helper functions for getting / setting configurations via sysfs */
ssize_t k2_max_inflight_show(struct elevator_queue *eq, char *s);

ssize_t k2_max_inflight_set(struct elevator_queue *eq, const char *s, 
                            size_t size);

static int ioprio_from_current(void)
{
	int prio;

	/* if task has no io prio, derive it from its nice value */
	if (current->io_context != NULL &&
		ioprio_valid(current->io_context->ioprio)) {
		prio = current->io_context->ioprio;
	} else {
		prio = IOPRIO_PRIO_VALUE(task_nice_ioclass(current), IOPRIO_NORM);
	}

	if (IOPRIO_PRIO_CLASS(prio) == IOPRIO_CLASS_RT) {
		int value = IOPRIO_PRIO_DATA(prio);
		/* can this happen??? */
		if (value >= IOPRIO_BE_NR || value < 0)
			prio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_RT, IOPRIO_NORM);
	}

	return(prio);
}

struct k2_data {
	unsigned int inflight;
	unsigned int max_inflight;

	/* further group real-time requests by I/O priority */
	struct list_head rt_reqs[IOPRIO_BE_NR];
	struct list_head be_reqs;

	spinlock_t lock;
};

/* configurations entries for sysfs (/sys/block/<dev>/queue/iosched/) */
static struct elv_fs_entry k2_attrs[] = {
    __ATTR(max_inflight, S_IRUGO | S_IWUSR, k2_max_inflight_show, 
                                            k2_max_inflight_set),
    __ATTR_NULL
};


ssize_t k2_max_inflight_show(struct elevator_queue *eq, char *s) 
{
	struct k2_data *k2d = eq->elevator_data;

	return(sprintf(s, "%u\n", k2d->max_inflight));
}

ssize_t k2_max_inflight_set(struct elevator_queue *eq, const char *s, 
                            size_t size)
{

	struct k2_data *k2d = eq->elevator_data;
	unsigned int old_max;
	unsigned int new_max;
	unsigned long flags;

	if (kstrtouint(s, 10, &new_max) >= 0) {
		spin_lock_irqsave(&k2d->lock, flags);
		old_max           = k2d->max_inflight;
		k2d->max_inflight = new_max;
		spin_unlock_irqrestore(&k2d->lock, flags);
		printk(KERN_INFO "k2: max_inflight set to %u\n", 
			k2d->max_inflight);
		
		return(size);
	}

	/* error, leave max_inflight as is */
	return(size);
}

/* Initialize the scheduler. */
static int k2_init_sched(struct request_queue *rq, struct elevator_type *et) 
{
	struct k2_data        *k2d;
	struct elevator_queue *eq;
	unsigned i;

	eq = elevator_alloc(rq, et);
	if (eq == NULL)
		return(-ENOMEM);
    
	/* allocate scheduler data from mem pool of request queue */
	k2d = kzalloc_node(sizeof(struct k2_data), GFP_KERNEL, rq->node);
	if (k2d == NULL) {
		kobject_put(&eq->kobj);
		return(-ENOMEM);
	}
	eq->elevator_data = k2d;

	k2d->inflight     =  0;
	k2d->max_inflight = 32;
	for (i = 0; i < IOPRIO_BE_NR; i++)
		INIT_LIST_HEAD(&k2d->rt_reqs[i]);

	INIT_LIST_HEAD(&k2d->be_reqs);
	spin_lock_init(&k2d->lock);

	rq->elevator = eq;
	printk(KERN_INFO "k2: I/O scheduler set up.\n"); 
	return(0);
}

/* Leave the scheduler. */
static void k2_exit_sched(struct elevator_queue *eq) 
{
	struct k2_data *k2d = eq->elevator_data;

	kfree(k2d);
}

static void k2_completed_request(struct request *r) 
{
	struct k2_data *k2d = r->q->elevator->elevator_data;
	unsigned long flags;
	unsigned int  counter;
	unsigned int  max_inf; 

	spin_lock_irqsave(&k2d->lock, flags);
	/* avoid negative counters */
	if (k2d->inflight > 0)
		k2d->inflight--;

	/* 
	 * Read both counters here to avoid stall situation if max_inflight  
	 * is modified simultaneously.
	 */
	counter = k2d->inflight;
	max_inf = k2d->max_inflight;
	spin_unlock_irqrestore(&k2d->lock, flags);

	/* 
	 * This completion call creates leeway for dispatching new requests.
	 * Rerunning the hw queues have to be done manually since we throttle
	 * request dispatching. Mind that this has to be executed in async mode.
	 */
	if (counter == (max_inf - 1))
		blk_mq_run_hw_queues(r->q, true);
}

static bool _k2_has_work(struct k2_data *k2d)
{
	unsigned int  i;

	assert_spin_locked(&k2d->lock);

	if (k2d->inflight >= k2d->max_inflight)
		return(false);

	if (! list_empty(&k2d->be_reqs))
		return(true);

	for (i = 0; i < IOPRIO_BE_NR; i++) {
		if (list_empty(&k2d->rt_reqs[i])) {
			return(true);
		}
	}

	return(false);
}

static bool k2_has_work(struct blk_mq_hw_ctx *hctx) 
{
	struct k2_data *k2d = hctx->queue->elevator->elevator_data;
	bool has_work;
	unsigned long flags;

	spin_lock_irqsave(&k2d->lock, flags);
	has_work = _k2_has_work(k2d);
	spin_unlock_irqrestore(&k2d->lock, flags);
    
	return(has_work);
}

static struct list_head* k2_queue_prio(struct k2_data * k2d, const int prio)
{
	// can we make a linear array out of it?
	if (IOPRIO_PRIO_CLASS(prio) == IOPRIO_CLASS_RT) {
		return(&k2d->rt_reqs[IOPRIO_PRIO_DATA(prio)]);
	} else {
		return(&k2d->be_reqs);
	}
}

/* Inserts a request into the scheduler queue. For now, at_head is ignored! */
void k2_insert_requests(struct blk_mq_hw_ctx *hctx, struct list_head *rqs,
                        bool at_head) 
{
	struct k2_data *k2d = hctx->queue->elevator->elevator_data;
	unsigned long flags;
	const int prio = ioprio_from_current();
	struct list_head *k2_queue = k2_queue_prio(k2d, prio);
	struct list_head *cur, *tmp;

	spin_lock_irqsave(&k2d->lock, flags);
	list_for_each_safe(cur, tmp, rqs) {
		struct request * r = list_entry(cur, struct request, queuelist);
		list_move_tail(cur, k2_queue);

		/* leave a message for tracing */
		blk_mq_sched_request_inserted(r);
	}
	spin_unlock_irqrestore(&k2d->lock, flags);
}

static struct request *k2_dispatch_request(struct blk_mq_hw_ctx *hctx) 
{
	struct k2_data *k2d = hctx->queue->elevator->elevator_data;
	struct request *r;
	unsigned long flags;
	unsigned int  i;

	spin_lock_irqsave(&k2d->lock, flags);
    
	/* inflight counter may have changed since last call to has_work */
	if (k2d->inflight >= k2d->max_inflight)
		goto abort;
    
	/* always prefer real-time requests */
	for (i = 0; i < IOPRIO_BE_NR; i++) {
		if (!list_empty(&k2d->rt_reqs[i])) {
			r = list_first_entry(&k2d->rt_reqs[i], struct request, 
					     queuelist);
			goto end;
		}
	}

	/* no rt rqs waiting: choose other workload      */
	if (!list_empty(&k2d->be_reqs)) {
		r = list_first_entry(&k2d->be_reqs, struct request, queuelist);
		goto end;
	}

abort:
	/* both request lists are empty or inflight counter is too high */
	spin_unlock_irqrestore(&k2d->lock, flags);    
	return(NULL);

end:
	list_del_init(&r->queuelist);
	k2d->inflight++;
	r->rq_flags |= RQF_STARTED;
	spin_unlock_irqrestore(&k2d->lock, flags);
	return(r);
}

static struct elevator_type k2_iosched = {
	.ops.mq = {
		.init_sched        = k2_init_sched,
		.exit_sched        = k2_exit_sched,

		.insert_requests   = k2_insert_requests,
		.has_work          = k2_has_work,
		.dispatch_request  = k2_dispatch_request,
		.completed_request = k2_completed_request,
	},
	.uses_mq        = true,
	.elevator_attrs = k2_attrs,
	.elevator_name  = "k2",
	.elevator_owner = THIS_MODULE,
};

static int __init k2_init(void) 
{
	printk(KERN_INFO "k2: Loading K2 I/O scheduler.\n");
	return(elv_register(&k2_iosched));
}

static void __exit k2_exit(void) 
{
	printk(KERN_INFO "k2: Unloading K2 I/O scheduler.\n");
	elv_unregister(&k2_iosched);
}

module_init(k2_init);
module_exit(k2_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Till Miemietz");
MODULE_DESCRIPTION("A work-constraining I/O scheduler with real-time notion.");
MODULE_VERSION("0.1");
