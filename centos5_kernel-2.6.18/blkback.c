/******************************************************************************
 * arch/xen/drivers/blkif/backend/main.c
 * 
 * Back-end of the driver for virtual block devices. This portion of the
 * driver exports a 'unified' block-device interface that can be accessed
 * by any operating system that implements a compatible front end. A 
 * reference front-end implementation can be found in:
 *  arch/xen/drivers/blkif/frontend
 * 
 * Copyright (c) 2003-2004, Keir Fraser & Steve Hand
 * Copyright (c) 2005, Christopher Clark
 * 
 * Debugging additions & private pending req queues for blkif by Michail Flouris.
 * Copyright (c) 2012, Michail Flouris <michail.flouris@onapp.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <linux/version.h>
#include <linux/autoconf.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <xen/balloon.h>
#include <asm/hypervisor.h>
#include <asm/hypercall.h>
#include <asm/maddr.h>
#include "common.h"

/*
 * These are rather arbitrary. They are fairly large because adjacent requests
 * pulled from a communication ring are quite likely to end up being part of
 * the same scatter/gather request at the disc.
 * 
 * ** TRY INCREASING 'blkif_reqs' IF WRITE SPEEDS SEEM TOO LOW **
 * 
 * This will increase the chances of being able to write whole tracks.
 * 64 should be enough to keep us competitive with Linux.
 */
static int blkif_reqs = 64;
module_param_named(reqs, blkif_reqs, int, 0);
MODULE_PARM_DESC(reqs, "Number of blkback requests to allocate");

/* Run-time switchable: /sys/module/blkback/parameters/ */
static unsigned int log_stats = 0;
static unsigned int debug_lvl = 0;
module_param(log_stats, int, 0644);
module_param(debug_lvl, int, 0644);

#undef ENABLE_PERIODIC_STATS

#ifdef ENABLE_PERIODIC_STATS
static atomic_t pending_free_count = ATOMIC_INIT(0);

static atomic_t pending_bios = ATOMIC_INIT(0);
static atomic_t pending_biolists = ATOMIC_INIT(0);

static atomic_t period_bios = ATOMIC_INIT(0);
static atomic_t period_completions = ATOMIC_INIT(0);
#endif

#define MAX_BLKBACK_COUNT 128
static atomic_t blkback_instances_count = ATOMIC_INIT(0);

/* Reusable page tables to work around dealloc and mem leaks */
#define MAX_PENDING_POOL_LEN	128
spinlock_t pending_page_pool_lock = SPIN_LOCK_UNLOCKED;
static atomic_t pending_page_pool_cnt = ATOMIC_INIT(0);
static atomic_t pending_page_total_cnt = ATOMIC_INIT(0);
static struct page **pending_page_pool[MAX_PENDING_POOL_LEN];

#define BLKBACK_INVALID_HANDLE (~0)


/*
 * Little helpful macro to figure out the index and virtual address of the
 * pending_pages[..]. For each 'pending_req' we have have up to
 * BLKIF_MAX_SEGMENTS_PER_REQUEST (11) pages. The seg would be from 0 through
 * 10 and would index in the pending_pages[..].
 */
static inline int vaddr_pagenr(pending_req_t *req, int seg)
{
	return (req - req->blkif->pending_reqs) * BLKIF_MAX_SEGMENTS_PER_REQUEST + seg;
}

static inline unsigned long vaddr(pending_req_t *req, int seg)
{
	unsigned long pfn = page_to_pfn(req->blkif->pending_pages[vaddr_pagenr(req, seg)]);
	return (unsigned long)pfn_to_kaddr(pfn);
}

#define pending_handle(_req, _seg) \
	(_req->blkif->pending_grant_handles[vaddr_pagenr(_req, _seg)])


static int do_block_io_op(blkif_t *blkif);
static void dispatch_rw_block_io(blkif_t *blkif,
				 blkif_request_t *req,
				 pending_req_t *pending_req);
static void make_response(blkif_t *blkif, u64 id,
			  unsigned short op, int st);

/******************************************************************
 * allocator for private (per blkif) pending req lists
 */
static int
blkif_alloc_pending_reqs(blkif_t *blkif)
{
	int i, mmap_pages;
	
	if ( atomic_inc_return(&blkback_instances_count) > MAX_BLKBACK_COUNT ) {
		atomic_dec(&blkback_instances_count);
		printk(KERN_ERR "%s ERROR: Max number of blkback instances %d reached!\n", __FUNCTION__, MAX_BLKBACK_COUNT);
		return -ENOMEM;
	}

	mmap_pages = blkif_reqs * BLKIF_MAX_SEGMENTS_PER_REQUEST;

	spin_lock(&pending_page_pool_lock);

	/* CHECK: free previous allocations... */
	if ( (i = atomic_dec_return(&pending_page_pool_cnt)) >= 0 ) {
		BUG_ON ( i < 0 || i >= MAX_PENDING_POOL_LEN );

		blkif->pending_pages = pending_page_pool[i];

	} else { /* No free pages in pool for reuse... */
		atomic_inc(&pending_page_pool_cnt);

		blkif->pending_pages = alloc_empty_pages_and_pagevec(mmap_pages);
		atomic_add(mmap_pages, &pending_page_total_cnt);
	}

	spin_unlock(&pending_page_pool_lock);

	blkif->pending_reqs          = kmalloc(sizeof(blkif->pending_reqs[0]) *
					blkif_reqs, GFP_KERNEL);
	blkif->pending_grant_handles = kmalloc(sizeof(blkif->pending_grant_handles[0]) *
					mmap_pages, GFP_KERNEL);

	if ( i >= 0 ) {
		printk(KERN_INFO "%s INIT: Reqs/inst: %d - Live Instance %d Uses: %d KB RAM (%d pages) [Pool Slot %d Avail %d Max %d]\n",
				current->comm, blkif_reqs, atomic_read(&blkback_instances_count),
				(int)(sizeof(blkif->pending_reqs[0]) * blkif_reqs + mmap_pages * PAGE_SIZE +
				sizeof(blkif->pending_grant_handles[0]) * mmap_pages +
				mmap_pages * sizeof(struct page *) ) / 1024, mmap_pages, i, atomic_read(&pending_page_pool_cnt), MAX_PENDING_POOL_LEN );
	} else {
		printk(KERN_INFO "%s INIT: Reqs/inst: %d - Live Instance %d Uses: %d KB RAM (%d pages) [Allocated %d NEW Pages]\n",
				current->comm, blkif_reqs, atomic_read(&blkback_instances_count),
				(int)(sizeof(blkif->pending_reqs[0]) * blkif_reqs + mmap_pages * PAGE_SIZE +
				sizeof(blkif->pending_grant_handles[0]) * mmap_pages +
				mmap_pages * sizeof(struct page *) ) / 1024, mmap_pages, mmap_pages );
	}
	printk(KERN_INFO "%s INIT: Total Mem Pages Allocated: %d (%d KB) - In Free Pool: %d (%d KB) [for all instances]\n",
			current->comm,
			atomic_read(&pending_page_total_cnt),
			atomic_read(&pending_page_total_cnt) * (int)(PAGE_SIZE / 1024),
			atomic_read(&pending_page_pool_cnt) * mmap_pages,
			atomic_read(&pending_page_pool_cnt) * mmap_pages * (int)(PAGE_SIZE / 1024) );

	if (!blkif->pending_reqs || !blkif->pending_grant_handles || !blkif->pending_pages)
		goto out_of_memory;

	/* NOTE: these may have been initialized in blkif_alloc(), but haven't been used... */
	blkif->pending_free_lock = SPIN_LOCK_UNLOCKED;
	init_waitqueue_head(&blkif->pending_free_wq);

	for (i = 0; i < mmap_pages; i++)
		blkif->pending_grant_handles[i] = BLKBACK_INVALID_HANDLE;

	memset(blkif->pending_reqs, 0, sizeof(blkif->pending_reqs));
	INIT_LIST_HEAD(&blkif->pending_free);

	for (i = 0; i < blkif_reqs; i++)
		list_add_tail(&blkif->pending_reqs[i].free_list, &blkif->pending_free);

#ifdef ENABLE_PERIODIC_STATS
	atomic_add( blkif_reqs,&pending_free_count ); /* count of free items in list */
#endif
	return 0;

 out_of_memory:
	if (blkif->pending_reqs)
		kfree(blkif->pending_reqs);
	if (blkif->pending_grant_handles)
		kfree(blkif->pending_grant_handles);
	free_empty_pages_and_pagevec(blkif->pending_pages, mmap_pages);
	printk(KERN_ERR "%s: out of memory\n", __FUNCTION__);
	return -ENOMEM;
}

void
blkif_free_pending_reqs(blkif_t *blkif)
{
	pending_req_t *req = NULL;
	int mmap_pages, pend_pg_cnt;
	unsigned long flags;
	
	printk(KERN_INFO "blkback exiting: FREE %d pending_reqs [BlkIf DomID: %d ptr: 0x%p]\n",
					blkif_reqs, (int)blkif->domid, blkif );
 
	mmap_pages = blkif_reqs * BLKIF_MAX_SEGMENTS_PER_REQUEST;
	//printk(KERN_DEBUG "%s mmap_pages = %d\n", current->comm, mmap_pages );

	spin_lock_irqsave(&blkif->pending_free_lock, flags);

	printk(KERN_DEBUG "blkback exiting: LOCKED pending_free_lock [BlkIf DomID: %d]\n", (int)blkif->domid );

	while (!list_empty(&blkif->pending_free)) {
		req = list_entry(blkif->pending_free.next, pending_req_t, free_list);
		list_del(&req->free_list);
	}

	spin_unlock_irqrestore(&blkif->pending_free_lock, flags);

	printk(KERN_DEBUG "blkback exiting: UNLOCKED pending_free_lock [BlkIf DomID: %d]\n", (int)blkif->domid );

	if ( blkif->pending_pages ) {

		spin_lock(&pending_page_pool_lock);

		if ( (pend_pg_cnt = atomic_inc_return(&pending_page_pool_cnt) - 1) < MAX_PENDING_POOL_LEN && pend_pg_cnt >= 0) {
			pending_page_pool[pend_pg_cnt] = blkif->pending_pages;

			spin_unlock(&pending_page_pool_lock);

			printk(KERN_DEBUG "blkif_free_pending_reqs() : storing pages in pool: pending_page_pool_cnt: %d < max %d\n",
						pend_pg_cnt+1, MAX_PENDING_POOL_LEN );
		} else {
			/* Rare mem leak coming up... */
			atomic_dec(&pending_page_pool_cnt);

			spin_unlock(&pending_page_pool_lock);

			printk(KERN_ERR "blkif_free_pending_reqs() ERROR: storing pages in pool: pending_page_pool_cnt: %d > max %d\n",
						pend_pg_cnt+1, MAX_PENDING_POOL_LEN );
		}
	}

	printk(KERN_DEBUG "blkback exiting: UNLOCKED pending_page_pool_lock [BlkIf DomID: %d]\n", (int)blkif->domid );

	if ( blkif->pending_grant_handles )
		kfree(blkif->pending_grant_handles);
	if ( blkif->pending_reqs )
		kfree(blkif->pending_reqs);

	if ( blkif->pending_pages )
		atomic_dec(&blkback_instances_count);

#ifdef ENABLE_PERIODIC_STATS
	atomic_sub( blkif_reqs, &pending_free_count ); /* count of free items in list */
#endif
}

/******************************************************************
 * misc small helpers
 */
static int have_pending_reqs(blkif_t *blkif)
{
	unsigned long flags;
	int have_reqs;

	spin_lock_irqsave(&blkif->pending_free_lock, flags);
	have_reqs = !list_empty(&blkif->pending_free);
	spin_unlock_irqrestore(&blkif->pending_free_lock, flags);

#if 0
#ifdef ENABLE_PERIODIC_STATS
	if (!have_reqs && atomic_read(&pending_free_count) != 0)
		printk(KERN_DEBUG "%s: BUG 0 in have_pending_reqs()!\n", current->comm);
	if (atomic_read(&pending_free_count) < 0)
		printk(KERN_DEBUG "%s: BUG count=%d in have_pending_reqs()!\n",
			current->comm, atomic_read(&pending_free_count) );
#endif
#endif

	return have_reqs;
}

static pending_req_t* alloc_req(blkif_t *blkif)
{
	pending_req_t *req = NULL;
	unsigned long flags;

	spin_lock_irqsave(&blkif->pending_free_lock, flags);
	if (!list_empty(&blkif->pending_free)) {
		req = list_entry(blkif->pending_free.next, pending_req_t, free_list);
		list_del(&req->free_list);
	}
	spin_unlock_irqrestore(&blkif->pending_free_lock, flags);

#ifdef ENABLE_PERIODIC_STATS
	if (req != NULL) /* if we got a spot, dec the counter */
		atomic_dec(&pending_free_count);
#endif
	return req;
}

static void free_req(pending_req_t *req)
{
	unsigned long flags;
	int was_empty;

	spin_lock_irqsave(&req->blkif->pending_free_lock, flags);
	was_empty = list_empty(&req->blkif->pending_free);
	list_add(&req->free_list, &req->blkif->pending_free);
	spin_unlock_irqrestore(&req->blkif->pending_free_lock, flags);

#ifdef ENABLE_PERIODIC_STATS
	atomic_inc(&pending_free_count);
#endif

	if (was_empty)
		wake_up(&req->blkif->pending_free_wq);
}

static void unplug_queue(blkif_t *blkif)
{
	if (blkif->plug == NULL)
		return;
	if (blkif->plug->unplug_fn)
		blkif->plug->unplug_fn(blkif->plug);
	blk_put_queue(blkif->plug);
	blkif->plug = NULL;
}

static void plug_queue(blkif_t *blkif, struct bio *bio)
{
	request_queue_t *q = bdev_get_queue(bio->bi_bdev);

	if (q == blkif->plug)
		return;
	unplug_queue(blkif);
	blk_get_queue(q);
	blkif->plug = q;
}

static void fast_flush_area(pending_req_t *req)
{
	struct gnttab_unmap_grant_ref unmap[BLKIF_MAX_SEGMENTS_PER_REQUEST];
	unsigned int i, invcount = 0;
	grant_handle_t handle;
	int ret;

	for (i = 0; i < req->nr_pages; i++) {
		handle = pending_handle(req, i);
		if (handle == BLKBACK_INVALID_HANDLE)
			continue;
		gnttab_set_unmap_op(&unmap[i], vaddr(req, i), GNTMAP_host_map,
				    handle);
		pending_handle(req, i) = BLKBACK_INVALID_HANDLE;
		invcount++;
	}

	ret = HYPERVISOR_grant_table_op(
		GNTTABOP_unmap_grant_ref, unmap, invcount);
	BUG_ON(ret);
}

/******************************************************************
 * DEBUG PERIODIC STATS TIMER
 */

static void print_stats(blkif_t *blkif)
{
	printk(KERN_DEBUG "%s: oo %3d  |  rd %4d  |  wr %4d\n",
	       current->comm, blkif->st_oo_req,
	       blkif->st_rd_req, blkif->st_wr_req);

	blkif->st_print = jiffies + msecs_to_jiffies(10 * 1000);
	blkif->st_rd_req = 0;
	blkif->st_wr_req = 0;
	blkif->st_oo_req = 0;
}

#ifdef ENABLE_PERIODIC_STATS
static int stat_timeout = 3*HZ;

static void
print_stats_periodic(unsigned long arg)
{
	blkif_t *blkif = (blkif_t *)arg;

	printk(KERN_ALERT "%s: PERIODIC hav_pend_rq=%d pend_free= %d pend_bios= %d pend_biolists= %d curr_bios= %d curr_compl= %d\n",
			current->comm, have_pending_reqs(blkif), atomic_read(&pending_free_count),
			atomic_read( &pending_bios ), atomic_read( &pending_biolists ),
			atomic_read( &period_bios ), atomic_read( &period_completions ) );
	print_stats(blkif);

	/* HANG DETECTION! */
	if (atomic_read( &period_bios ) == 0 && atomic_read( &period_completions ) == 0 &&
			atomic_read( &pending_bios ) > 10 ) {
		printk(KERN_ALERT "%s: HANG DETECTED!!!\n", current->comm);
	}

	atomic_set( &period_bios, 0 );
	atomic_set( &period_completions, 0 );

	/* CAUTION: if the timer is not pending, mod_timer() will RE-ACTIVATE it ! */
	mod_timer(&blkif->ti, jiffies + stat_timeout);
}

static void
start_periodic_stat_timer(blkif_t *lo)
{
	init_timer(&lo->ti);
	lo->ti.function = print_stats_periodic;
	lo->ti.data = (unsigned long)lo;
	lo->ti.expires = jiffies + stat_timeout;
	add_timer(&lo->ti);
}

static void
stop_periodic_stat_timer(blkif_t *lo)
{
	del_timer(&lo->ti);
}
#endif

/******************************************************************
 * SCHEDULER FUNCTIONS
 */

int blkif_schedule(void *arg)
{
	blkif_t *blkif = arg;
	struct vbd *vbd = &blkif->vbd;

	blkif_get(blkif);

	//printk(KERN_INFO "%s: started [BlkIf DomID: %d ptr: 0x%p]\n", current->comm, (int)blkif->domid, blkif);
	printk(KERN_INFO "%s: started [BlkIf DomID: %d]\n", current->comm, (int)blkif->domid);

	if ( blkif_alloc_pending_reqs(blkif) ) { /* alloc private pending req list */
		printk(KERN_ERR "%s: ERROR: failed to initialize req queue [BlkIf DomID: %d]\n", current->comm, (int)blkif->domid);
		blkif_put(blkif);
		return -ENOMEM;
	}
#ifdef ENABLE_PERIODIC_STATS
	if (debug_lvl)
		start_periodic_stat_timer(blkif);
#endif
	while (!kthread_should_stop()) {
		if (unlikely(vbd->size != vbd_size(vbd)))
			vbd_resize(blkif);

		wait_event_interruptible(
			blkif->wq,
			blkif->waiting_reqs || kthread_should_stop());
		wait_event_interruptible(
			blkif->pending_free_wq,
			have_pending_reqs(blkif) || kthread_should_stop());

		blkif->waiting_reqs = 0;
		smp_mb(); /* clear flag *before* checking for work */

		if (do_block_io_op(blkif)) {

#ifdef ENABLE_PERIODIC_STATS
//			printk(KERN_ALERT "%s: blkif_schedule FULL LIST have_pend_reqs=%d pend_free_count= %d pend_bios= %d pend_biolists= %d\n",
//					current->comm, have_pending_reqs(blkif), atomic_read(&pending_free_count),
//					atomic_read( &pending_bios ), atomic_read( &pending_biolists ) );
			print_stats(blkif);
#endif
			blkif->waiting_reqs = 1;
		}
		unplug_queue(blkif);

		if (log_stats && time_after(jiffies, blkif->st_print))
			print_stats(blkif);
	}
#ifdef ENABLE_PERIODIC_STATS
	if (debug_lvl)
		stop_periodic_stat_timer(blkif);
#endif
	if (log_stats)
		print_stats(blkif);

	printk(KERN_INFO "%s: exiting [BlkIf DomID: %d]\n", current->comm, (int)blkif->domid);

	blkif->xenblkd = NULL;
	blkif_put(blkif);

	return 0;
}

/******************************************************************
 * COMPLETION CALLBACK -- Called as bh->b_end_io()
 */

static void __end_block_io_op(pending_req_t *pending_req, int uptodate)
{
	/* An error fails the entire request. */
	if (!uptodate) {
		printk(KERN_ALERT "[%s - DomID: %d] Buffer not up-to-date at end of operation [I/O Error]\n",
				current->comm, (int)pending_req->blkif->domid);
#if 0
		printk(KERN_ALERT "%s DEBUG: end_block_io_op pendcnt= %d pending_bios= %d pending_biolists= %d\n",
				current->comm, atomic_read(&pending_req->pendcnt),
				atomic_read( &pending_bios ), atomic_read( &pending_biolists ) );
		printk(KERN_ALERT "%s DEBUG: end_block_io_op have_pending_reqs= %d pending_free_count= %d\n",
				current->comm, have_pending_reqs(pending_req->blkif), atomic_read(&pending_free_count) );
		print_stats(pending_req->blkif);
#endif
		pending_req->status = BLKIF_RSP_ERROR;
	}

	if (atomic_dec_and_test(&pending_req->pendcnt)) {
#ifdef ENABLE_PERIODIC_STATS
		atomic_dec( &pending_biolists );
#endif
		fast_flush_area(pending_req);
		make_response(pending_req->blkif, pending_req->id,
			      pending_req->operation, pending_req->status);
		blkif_put(pending_req->blkif);
		free_req(pending_req);
	}
}

/*
 * bio callback.
 */
static int end_block_io_op(struct bio *bio, unsigned int done, int error)
{
	if (bio->bi_size != 0)
		return 1;
#ifdef ENABLE_PERIODIC_STATS
	atomic_dec( &pending_bios );
	atomic_inc( &period_completions );
#endif
	__end_block_io_op(bio->bi_private, !error);
	bio_put(bio);
	return error;
}


/******************************************************************************
 * NOTIFICATION FROM GUEST OS.
 */

static void blkif_notify_work(blkif_t *blkif)
{
	blkif->waiting_reqs = 1;
	wake_up(&blkif->wq);
	smp_mb(); /* make sure flag is checked */
}

irqreturn_t blkif_be_int(int irq, void *dev_id, struct pt_regs *regs)
{
	blkif_notify_work(dev_id);
	return IRQ_HANDLED;
}



/******************************************************************
 * DOWNWARD CALLS -- These interface with the block-device layer proper.
 */

static int
__do_block_io_op(blkif_t *blkif)
{
	blkif_back_rings_t *blk_rings = &blkif->blk_rings;
	blkif_request_t req;
	pending_req_t *pending_req;
	RING_IDX rc, rp;
	int more_to_do = 0;

	rc = blk_rings->common.req_cons;
	rp = blk_rings->common.sring->req_prod;
	rmb(); /* Ensure we see queued requests up to 'rp'. */

	while (rc != rp) {

		if (RING_REQUEST_CONS_OVERFLOW(&blk_rings->common, rc)) {
			//printk(KERN_DEBUG "%s DEBUG: RING_REQUEST_CONS_OVERFLOW break!\n", current->comm);
			break;
		}

		if (kthread_should_stop()) {
			//printk(KERN_DEBUG "%s DEBUG: kthread_should_stop break!\n", current->comm);
			more_to_do = 1;
			break;
		}

		pending_req = alloc_req(blkif);
		if (NULL == pending_req) {
			//printk(KERN_DEBUG "%s DEBUG: alloc_req returned NULL!\n", current->comm);
			blkif->st_oo_req++;
			more_to_do = 1;
			break;
		}

		switch (blkif->blk_protocol) {
		case BLKIF_PROTOCOL_NATIVE:
			memcpy(&req, RING_GET_REQUEST(&blk_rings->native, rc), sizeof(req));
			break;
		case BLKIF_PROTOCOL_X86_32:
			blkif_get_x86_32_req(&req, RING_GET_REQUEST(&blk_rings->x86_32, rc));
			break;
		case BLKIF_PROTOCOL_X86_64:
			blkif_get_x86_64_req(&req, RING_GET_REQUEST(&blk_rings->x86_64, rc));
			break;
		default:
			BUG();
		}
		blk_rings->common.req_cons = ++rc; /* before make_response() */

		switch (req.operation) {
		case BLKIF_OP_READ:
			blkif->st_rd_req++;
			dispatch_rw_block_io(blkif, &req, pending_req);
			break;
		case BLKIF_OP_WRITE:
			blkif->st_wr_req++;
			dispatch_rw_block_io(blkif, &req, pending_req);
			break;
		default:
			/* A good sign something is wrong: sleep for a while to
			 * avoid excessive CPU consumption by a bad guest. */
			msleep(1);
			DPRINTK("error: unknown block io operation [%d]\n",
				req.operation);
			make_response(blkif, req.id, req.operation,
				      BLKIF_RSP_ERROR);
			pending_req->blkif = blkif;
			free_req(pending_req);
			break;
		}

		/* Yield point for this unbounded loop. */
		cond_resched();
	}

	return more_to_do;
}

static int
do_block_io_op(blkif_t *blkif)
{
	union blkif_back_rings *blk_rings = &blkif->blk_rings;
	int more_to_do;

	do {
		more_to_do = __do_block_io_op(blkif);
		if (more_to_do)
			break;

		RING_FINAL_CHECK_FOR_REQUESTS(&blk_rings->common, more_to_do);
	} while (more_to_do);

	return more_to_do;
}

static void dispatch_rw_block_io(blkif_t *blkif,
				 blkif_request_t *req,
				 pending_req_t *pending_req)
{
	extern void ll_rw_block(int rw, int nr, struct buffer_head * bhs[]);
	int operation = (req->operation == BLKIF_OP_WRITE) ? WRITE : READ;
	struct gnttab_map_grant_ref map[BLKIF_MAX_SEGMENTS_PER_REQUEST];
	struct phys_req preq;
	struct { 
		unsigned long buf; unsigned int nsec;
	} seg[BLKIF_MAX_SEGMENTS_PER_REQUEST];
	unsigned int nseg;
	struct bio *bio = NULL, *biolist[BLKIF_MAX_SEGMENTS_PER_REQUEST];
	int ret, i, nbio = 0;

	pending_req->blkif     = blkif;

	/* Check that number of segments is sane. */
	nseg = req->nr_segments;
	if (unlikely(nseg == 0) || 
	    unlikely(nseg > BLKIF_MAX_SEGMENTS_PER_REQUEST)) {
		DPRINTK("Bad number of segments in request (%d)\n", nseg);
		goto fail_response;
	}

	preq.dev           = req->handle;
	preq.sector_number = req->sector_number;
	preq.nr_sects      = 0;

	pending_req->id        = req->id;
	pending_req->operation = operation;
	pending_req->status    = BLKIF_RSP_OKAY;
	pending_req->nr_pages  = nseg;

	for (i = 0; i < nseg; i++) {
		uint32_t flags;

		seg[i].nsec = req->seg[i].last_sect -
			req->seg[i].first_sect + 1;

		if ((req->seg[i].last_sect >= (PAGE_SIZE >> 9)) ||
		    (req->seg[i].last_sect < req->seg[i].first_sect))
			goto fail_response;
		preq.nr_sects += seg[i].nsec;

		flags = GNTMAP_host_map;
		if ( operation == WRITE )
			flags |= GNTMAP_readonly;
		gnttab_set_map_op(&map[i], vaddr(pending_req, i), flags,
				  req->seg[i].gref, blkif->domid);
	}

	ret = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, map, nseg);
	BUG_ON(ret);

	for (i = 0; i < nseg; i++) {
		if (unlikely(map[i].status != 0)) {
			DPRINTK("invalid buffer -- could not remap it\n");
			map[i].handle = BLKBACK_INVALID_HANDLE;
			ret |= 1;
		}

		pending_handle(pending_req, i) = map[i].handle;

		if (ret)
			continue;

		set_phys_to_machine(__pa(vaddr(
			pending_req, i)) >> PAGE_SHIFT,
			FOREIGN_FRAME(map[i].dev_bus_addr >> PAGE_SHIFT));
		seg[i].buf  = map[i].dev_bus_addr | 
			(req->seg[i].first_sect << 9);
	}

	if (ret)
		goto fail_flush;

	if (vbd_translate(&preq, blkif, operation) != 0) {
		DPRINTK("access denied: %s of [%llu,%llu] on dev=%04x\n", 
			operation == READ ? "read" : "write",
			preq.sector_number,
			preq.sector_number + preq.nr_sects, preq.dev);
		goto fail_flush;
	}

	for (i = 0; i < nseg; i++) {
		if (((int)preq.sector_number|(int)seg[i].nsec) &
		    ((bdev_hardsect_size(preq.bdev) >> 9) - 1)) {
			DPRINTK("Misaligned I/O request from domain %d",
				blkif->domid);
			goto fail_put_bio;
		}

		while ((bio == NULL) ||
		       (bio_add_page(bio,
				     virt_to_page(vaddr(pending_req, i)),
				     seg[i].nsec << 9,
				     seg[i].buf & ~PAGE_MASK) == 0)) {
			bio = biolist[nbio++] = bio_alloc(GFP_KERNEL, nseg-i);
			if (unlikely(bio == NULL))
				goto fail_put_bio;

			bio->bi_bdev    = preq.bdev;
			bio->bi_private = pending_req;
			bio->bi_end_io  = end_block_io_op;
			bio->bi_sector  = preq.sector_number;
		}

		preq.sector_number += seg[i].nsec;
	}

	plug_queue(blkif, bio);
	atomic_set(&pending_req->pendcnt, nbio);
	blkif_get(blkif);

#ifdef ENABLE_PERIODIC_STATS
	atomic_add( nbio, &pending_bios );
	atomic_add( nbio, &period_bios );

	atomic_inc( &pending_biolists );
#endif

	for (i = 0; i < nbio; i++)
		submit_bio(operation, biolist[i]);

	if (operation == READ) {
		blkif->st_rd_sect += preq.nr_sects;
	} else if (operation == WRITE) {
		blkif->st_wr_sect += preq.nr_sects;
	}

	return;

 fail_put_bio:
	for (i = 0; i < (nbio-1); i++)
		bio_put(biolist[i]);
 fail_flush:
	fast_flush_area(pending_req);
 fail_response:
	make_response(blkif, req->id, req->operation, BLKIF_RSP_ERROR);
	free_req(pending_req);
	msleep(1); /* back off a bit */
} 


/******************************************************************
 * MISCELLANEOUS SETUP / TEARDOWN / DEBUGGING
 */


static void make_response(blkif_t *blkif, u64 id,
			  unsigned short op, int st)
{
	blkif_response_t  resp;
	unsigned long     flags;
	blkif_back_rings_t *blk_rings = &blkif->blk_rings;
	int notify;

	resp.id        = id;
	resp.operation = op;
	resp.status    = st;

	spin_lock_irqsave(&blkif->blk_ring_lock, flags);
	/* Place on the response ring for the relevant domain. */
	switch (blkif->blk_protocol) {
	case BLKIF_PROTOCOL_NATIVE:
		memcpy(RING_GET_RESPONSE(&blk_rings->native, blk_rings->native.rsp_prod_pvt),
		       &resp, sizeof(resp));
		break;
	case BLKIF_PROTOCOL_X86_32:
		memcpy(RING_GET_RESPONSE(&blk_rings->x86_32, blk_rings->x86_32.rsp_prod_pvt),
		       &resp, sizeof(resp));
		break;
	case BLKIF_PROTOCOL_X86_64:
		memcpy(RING_GET_RESPONSE(&blk_rings->x86_64, blk_rings->x86_64.rsp_prod_pvt),
		       &resp, sizeof(resp));
		break;
	default:
		BUG();
	}
	blk_rings->common.rsp_prod_pvt++;
	RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(&blk_rings->common, notify);
	spin_unlock_irqrestore(&blkif->blk_ring_lock, flags);
	if (notify)
		notify_remote_via_irq(blkif->irq);
}

static int __init blkif_init(void)
{
	if (!is_running_on_xen())
		return -ENODEV;

	if ( blkif_reqs < 64 ) {
		printk(KERN_ERR "%s INIT: Too low blkif_reqs value %d! Must be >= 64.\n",
				current->comm, blkif_reqs);
		return -EINVAL;
	}

	blkif_interface_init();

#ifdef ENABLE_PERIODIC_STATS
	atomic_set( &pending_free_count, 0 ); /* count of free items in list */
#endif

	blkif_xenbus_init();

	printk(KERN_INFO "Blkback C5 (blkbk) [Build: %s %s]: Loaded OK.\n", __DATE__, __TIME__);

	return 0;
}

module_init(blkif_init);

MODULE_LICENSE("Dual BSD/GPL");
