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
#include <linux/printk.h>

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

/*
 * blk_mq_sched_request_inserted() is EXPORT_SYMBOL_GPL'ed, but it is declared
 * in the header file block/blk-mq-sched.h, which is not part of the installed
 * kernel headers a module is built against (only part of the full source).
 * Therefore, we forward-declare it again here.
 * (implicitly declared functions are an error.)
 */
extern void blk_mq_sched_request_inserted(struct request *rq);
extern bool blk_mq_sched_try_merge(struct request_queue *q, struct bio *bio,
		struct request **merged_request);

/* helper functions for getting / setting configurations via sysfs */
ssize_t k2_max_inflight_show(struct elevator_queue *eq, char *s);

ssize_t k2_max_inflight_set(struct elevator_queue *eq, const char *s, 
                            size_t size);

#define K2_NUM_QUEUES    (IOPRIO_BE_NR  * 2 + 1)
#define K2_NUM_SORTLISTS (K2_NUM_QUEUES * 2)

struct k2_data {
	unsigned int inflight;
	unsigned int max_inflight;

	/*
	 * K2 request queues:
	 *   - 1 real-time class with 8 priority levels
	 *   - 1 best effort class with 8 priority levels
	 *   - 1 idle class with one level
	 * ioprio to queue index mapping:
	 * first 8 entries are the RT queues, followed by the 8 entries for the
	 * best-effort queues. the last entry is the idle queue.
	 * See k2_queue_idx() for ioprio to index mapping.
	 */
	struct list_head queues[K2_NUM_QUEUES];

	/* Sector-ordered lists for request front merging, one for each priority.
	 * Priority-to-index-encoding is the same as for the request queues.
	 * Request merging is done per request type (read or write), hence
	 * twice the number of lists.
	 */
	struct rb_root sort_list[K2_NUM_SORTLISTS];

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

static unsigned k2_queue_idx(const unsigned short ioprio)
{
	const unsigned class = IOPRIO_PRIO_CLASS(ioprio);
	const unsigned data = IOPRIO_PRIO_DATA(ioprio);
	const unsigned idx = (class - 1) * IOPRIO_BE_NR + data;

	BUG_ON(!ioprio_valid(ioprio));

	return idx;
}

static struct list_head *
k2_queue(struct k2_data * const k2d, const unsigned short ioprio)
{
	const unsigned idx = k2_queue_idx(ioprio);

	return &k2d->queues[idx];
}

static struct rb_root *
k2_rb_root(struct k2_data * const k2d, const unsigned short ioprio, const int data_dir)
{
	const unsigned idx_ = k2_queue_idx(ioprio);
	const unsigned idx = data_dir * K2_NUM_QUEUES + idx_;

	return &k2d->sort_list[idx];
}

static struct rb_root *
k2_rb_root_req(struct k2_data * const k2d, const struct request * const r)
{
	return k2_rb_root(k2d, r->ioprio, rq_data_dir(r));
}

static struct rb_root *
k2_rb_root_bio(struct k2_data * const k2d, const struct bio * const bio)
{
	return k2_rb_root(k2d, bio_prio(bio), bio_data_dir(bio));
}

static void
k2_add_rq_rb(struct k2_data * const k2d, struct request *const rq)
{
	struct rb_root *root = k2_rb_root_req(k2d, rq);
	elv_rb_add(root, rq);
}

static void
k2_del_rq_rb(struct k2_data * const k2d, struct request * const rq)
{
	struct rb_root *root = k2_rb_root_req(k2d, rq);
	elv_rb_del(root, rq);
}

static void k2_remove_request(struct request_queue *q, struct request *r)
{
	struct k2_data *k2d = q->elevator->elevator_data;

	list_del_init(&r->queuelist);

	/*
	 * During an insert merge r might have not been added to the rb-tree yet
	 */
	if (!RB_EMPTY_NODE(&r->rb_node))
		k2_del_rq_rb(k2d, r);

	elv_rqhash_del(q, r);
	if (q->last_merge == r)
		q->last_merge = NULL;
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

	for (i = 0; i < K2_NUM_QUEUES; ++i) {
		INIT_LIST_HEAD(&k2d->queues[i]);
	}

	for (i = 0; i < K2_NUM_SORTLISTS; ++i) {
		k2d->sort_list[i] = RB_ROOT;
	}

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

	pr_info("Req %px completed\n", r);

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

	for (i = 0; i < K2_NUM_QUEUES; ++i) {
		if (! list_empty(&k2d->queues[i])) {
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

static void k2_ioprio_from_task(int *class, int *value) 
{
	if (current->io_context == NULL || 
		!ioprio_valid(current->io_context->ioprio)) {
		*class = task_nice_ioclass(current);
		*value = IOPRIO_NORM;
	} else {
		*class = IOPRIO_PRIO_CLASS(current->io_context->ioprio);
		*value = IOPRIO_PRIO_VALUE(*class, current->io_context->ioprio);
	}
}

/* Inserts a request into the scheduler queue. For now, at_head is ignored! */
static void k2_insert_requests(struct blk_mq_hw_ctx *hctx, struct list_head *rqs,
				bool at_head) 
{
	struct request_queue *q = hctx->queue;
	struct k2_data *k2d = hctx->queue->elevator->elevator_data;
	struct list_head *cur, *tmp;

	unsigned long flags;

	spin_lock_irqsave(&k2d->lock, flags);
	list_for_each_safe(cur, tmp, rqs) {
		struct request *r = list_entry(cur, struct request, queuelist);
		const unsigned ioprio = r->ioprio;

		// Add request to per-prio FIFO queue
		struct list_head * queue = k2_queue(k2d, ioprio);
		list_move_tail(cur, queue);

		// keep per-prio sector-ordered lists for merging
		k2_add_rq_rb(k2d, r);
		if (rq_mergeable(r)) {
			elv_rqhash_add(q, r);
			if (!q->last_merge)
				q->last_merge = r;
		} else {
			pr_info("Request not mergeable\n");
		}

		/* leave a message for tracing */
		blk_mq_sched_request_inserted(r);
	}
	spin_unlock_irqrestore(&k2d->lock, flags);
}

static struct request *k2_dispatch_request(struct blk_mq_hw_ctx *hctx) 
{
	struct request_queue *q = hctx->queue;
	struct k2_data *k2d = hctx->queue->elevator->elevator_data;
	struct request *r = NULL;
	unsigned long flags;
	unsigned int  i;

	spin_lock_irqsave(&k2d->lock, flags);
    
	/* inflight counter may have changed since last call to has_work */
	if (k2d->inflight >= k2d->max_inflight)
		goto unlock_out;
    
	/* always prefer real-time requests */
	for (i = 0; i < K2_NUM_QUEUES; ++i) {
		r = list_first_entry_or_null(&k2d->queues[i], struct request, 
					     queuelist);
		if(r != NULL) {
			break;
		}
	}

	k2_remove_request(q, r);
	k2d->inflight++;
	r->rq_flags |= RQF_STARTED;

unlock_out:
	spin_unlock_irqrestore(&k2d->lock, flags);
	return(r);
}

static bool k2_bio_merge(struct blk_mq_hw_ctx *hctx, struct bio *bio)
{
	struct request_queue *q = hctx->queue;
	struct k2_data *k2d = q->elevator->elevator_data;
	struct request *free = NULL;
	unsigned long flags;
	bool ret;

	spin_lock_irqsave(&k2d->lock, flags);
	ret = blk_mq_sched_try_merge(q, bio, &free);
	spin_unlock_irqrestore(&k2d->lock, flags);

	if (free)
		blk_mq_free_request(free);

	return(ret);
}

/*
 * Tell the MQ-Layer if it is ok to merge bio with r.
 * Callback from the path of blk_mq_sched_try_merge, which we call in k2_bio_merge.
 * Future versions of the kernel, will check ioprio before merging, but not our kernel
 * version target of 4.15.
 * Note: elv_merge gets r from q->last_merge, or the out-param from k2_request_merge.
 * (we don't use the elv_rbhash-infrastructure)
 */
static bool k2_allow_bio_merge(struct request_queue *q, struct request * r, struct bio * bio)
{
	return r->ioprio == bio_prio(bio);
}

/*
 * Find a back-merge with the correct I/O-prio
 */
static struct request *
k2_find_backmerge(struct request_queue * q, struct bio * const  bio)
{
#define ELV_ON_HASH(rq) ((rq)->rq_flags & RQF_HASHED)
#define rq_hash_key(rq)	(blk_rq_pos(rq) + blk_rq_sectors(rq))

	struct elevator_queue *e = q->elevator;
	struct hlist_node *next;
	struct request *r;
	const sector_t sector = bio->bi_iter.bi_sector;
	const unsigned ioprio = bio_prio(bio);

	hash_for_each_possible_safe(e->hash, r, next, hash, sector) {
		BUG_ON(!ELV_ON_HASH(r));

		if (unlikely(!rq_mergeable(r))) {
			elv_rqhash_del(q, r);
			continue;
		}

		if (rq_hash_key(r) == sector && r->ioprio == ioprio)
			return r;
	}

	return NULL;
}


static int k2_request_merge(struct request_queue *q, struct request **r, struct bio *bio)
{
	struct k2_data *k2d = q->elevator->elevator_data;
	struct rb_root * root = k2_rb_root_bio(k2d, bio);
	struct request *__rq = NULL;
	const sector_t end_sector = bio_end_sector(bio);

	assert_spin_locked(&k2d->lock);

	/*
	 * check for back merges. elv_* might not have found one (multiple prios),
	 * or we might have denied one in k2_allow_bio_merge
	 */
	__rq = k2_find_backmerge(q, bio);
	if(__rq && elv_bio_merge_ok(__rq, bio)) {
		// the first sector of bio better be one after the last sector of __rq!
		BUG_ON((blk_rq_pos(__rq) + blk_rq_sectors(__rq) != bio->bi_iter.bi_sector));
		*r = __rq;
		return(ELEVATOR_BACK_MERGE);
	}

	__rq = elv_rb_find(root, end_sector);
	if (__rq && elv_bio_merge_ok(__rq, bio)) {
		// one past the last sector of the new bio has to be first sector of __rq.
		BUG_ON(end_sector != blk_rq_pos(__rq));
		*r = __rq;
		return(ELEVATOR_FRONT_MERGE);
	}

	return(ELEVATOR_NO_MERGE);
}

static void k2_request_merged(struct request_queue *q, struct request *req,
				enum elv_merge type)
{
	struct k2_data *k2d = q->elevator->elevator_data;

	/*
	 * if the merge was a front merge, we need to reposition request, because the
	 * request has a new first sector and the rb-tree is ordered by first sector
	 * of the requests.
	 */
	if (type == ELEVATOR_FRONT_MERGE) {
		k2_del_rq_rb(k2d, req);
		k2_add_rq_rb(k2d, req);
	}
}

/*
 * This function is called to notify the scheduler that the requests
 * rq and 'next' have been merged, with 'next' going away.
 */
static void k2_requests_merged(struct request_queue *q, struct request *rq,
				struct request *next)
{
	k2_remove_request(q, next);
}

static struct elevator_type k2_iosched = {
	.ops.mq = {
		.init_sched        = k2_init_sched,
		.exit_sched        = k2_exit_sched,

		.insert_requests   = k2_insert_requests,
		.has_work          = k2_has_work,
		.dispatch_request  = k2_dispatch_request,
		.completed_request = k2_completed_request,

		.allow_merge       = k2_allow_bio_merge,
		.bio_merge         = k2_bio_merge,
		.request_merge     = k2_request_merge,
		.request_merged    = k2_request_merged,
		.requests_merged   = k2_requests_merged,
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
