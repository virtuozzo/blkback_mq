/******************************************************************************
 * blkback/vbd.c
 * 
 * Routines for managing virtual block devices (VBDs).
 * 
 * Copyright (c) 2003-2005, Keir Fraser & Steve Hand
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

#include "common.h"

#define vbd_sz(_v)   ((_v)->bdev->bd_part ?				\
	(_v)->bdev->bd_part->nr_sects : (_v)->bdev->bd_disk->capacity)

unsigned long long vbd_size(struct vbd *vbd)
{
	return vbd_sz(vbd);
}

unsigned int vbd_info(struct vbd *vbd)
{
	return vbd->type | (vbd->readonly?VDISK_READONLY:0);
}

unsigned long vbd_secsize(struct vbd *vbd)
{
	return bdev_hardsect_size(vbd->bdev);
}

/*
 * Check if the domain owning the device can be determined to be PV. The check
 * is based on the /vm/<uuid>/image xenstore record. On success, return 0, on
 * failure, return -1.
 */
static int vbd_is_pv(struct xenbus_device *dev)
{
	int id, err;
	char buf[1024];
	char *uuid, *image;
	int ret = -1;

	err = xenbus_scanf(XBT_NIL, dev->nodename, "frontend-id", "%d", &id);
	if (err != 1) {
		xenbus_dev_error(dev, err, "Can't read frontend-id");
		return ret;
	}

	sprintf(buf, "/local/domain/%d", id);
	uuid = xenbus_read(XBT_NIL, buf, "vm", NULL);
	if (IS_ERR(uuid)) {
		xenbus_dev_error(dev, PTR_ERR(uuid), "Can't read domain uuid");
		return ret;
	}

	image = xenbus_read(XBT_NIL, uuid, "image", NULL);
	if (IS_ERR(image))
		xenbus_dev_error(dev, PTR_ERR(image),
				 "Can't read 'image'");
	else {
		if (strncmp(image, "(hvm ", 5) != 0)
			ret = 0;
		kfree(image);
	}

	kfree(uuid);
	return ret;
}

int vbd_create(blkif_t *blkif, blkif_vdev_t handle, unsigned major,
	       unsigned minor, int readonly)
{
	struct vbd *vbd;
	struct block_device *bdev;

	vbd = &blkif->vbd;
	vbd->handle   = handle; 
	vbd->readonly = readonly;
	vbd->type     = 0;

	vbd->pdevice  = MKDEV(major, minor);

	bdev = open_by_devnum(vbd->pdevice,
			      vbd->readonly ? FMODE_READ : FMODE_WRITE);

	if (IS_ERR(bdev)) {
		DPRINTK("vbd_creat: device %08x could not be opened.\n",
			vbd->pdevice);
		return -ENOENT;
	}

	vbd->bdev = bdev;

	/* xen blkback supports CD-ROMs only for PV guests, because HVM guests
	 * might ask the host operator to change media, and only qemu-dm
	 * supports that */
	if (vbd->bdev->bd_disk == NULL ||
	    ((vbd->bdev->bd_disk->flags & GENHD_FL_CD) &&
	     vbd_is_pv(blkif->be->dev) == -1)) {
		DPRINTK("vbd_creat: device %08x doesn't exist.\n",
			vbd->pdevice);
		vbd_free(vbd);
		return -ENOENT;
	}

	vbd->size = vbd_size(vbd);

	if (vbd->bdev->bd_disk->flags & GENHD_FL_CD)
		vbd->type |= VDISK_CDROM;
	if (vbd->bdev->bd_disk->flags & GENHD_FL_REMOVABLE)
		vbd->type |= VDISK_REMOVABLE;

	//DPRINTK("Successful creation of handle=%04x (dom=%u)\n",
	//	handle, blkif->domid);
	return 0;
}

void vbd_free(struct vbd *vbd)
{
	if (vbd->bdev)
		blkdev_put(vbd->bdev);
	vbd->bdev = NULL;
}

int vbd_translate(struct phys_req *req, blkif_t *blkif, int operation)
{
	struct vbd *vbd = &blkif->vbd;
	int rc = -EACCES;

	if ((operation == WRITE) && vbd->readonly)
		goto out;

	if (unlikely((req->sector_number + req->nr_sects) > vbd_sz(vbd)))
		goto out;

	req->dev  = vbd->pdevice;
	req->bdev = vbd->bdev;
	rc = 0;

 out:
	return rc;
}

void vbd_resize(blkif_t *blkif)
{
	struct vbd *vbd = &blkif->vbd;
	struct xenbus_transaction xbt;
	int err;
	struct xenbus_device *dev = blkif->be->dev;
	unsigned long long new_size = vbd_size(vbd);

	printk(KERN_INFO "VBD Resize: Domid: %u, Device: (%u, %u), "
	       "New Size: %Lu sectors\n", (unsigned)blkif->domid,
	       (unsigned)MAJOR(vbd->pdevice), (unsigned)MINOR(vbd->pdevice),
	       new_size);
	vbd->size = new_size;
again:
	err = xenbus_transaction_start(&xbt);
	if (err) {
		printk(KERN_WARNING "Error starting transaction");
		return;
	}
	err = xenbus_printf(xbt, dev->nodename, "sectors", "%Lu",
			    vbd_size(vbd));
	if (err) {
		printk(KERN_WARNING "Error writing new size");
		goto abort;
	}
	/*
	 * Write the current state; we will use this to synchronize
	 * the front-end. If the current state is "connected" the
	 * front-end will get the new size information online.
	 */
	err = xenbus_printf(xbt, dev->nodename, "state", "%d", dev->state);
	if (err) {
		printk(KERN_WARNING "Error writing the state");
		goto abort;
	}

	err = xenbus_transaction_end(xbt, 0);
	if (err == -EAGAIN)
		goto again;
	if (err)
		printk(KERN_WARNING "Error ending transaction");
	return;
abort:
	xenbus_transaction_end(xbt, 1);
}
