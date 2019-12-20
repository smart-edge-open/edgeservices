/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file libnes_queue.h
 * @brief Header file for libnes_queue
 */

#ifndef _LIBNES_QUEUE_H_
#define _LIBNES_QUEUE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <unistd.h>
#include <rte_spinlock.h>
#include <rte_atomic.h>

#define NES_QUEUE_RETRY 10

#define NES_QUEUE_FOREACH(item, queue) \
	for ((item) = nes_queue_first_busy((queue)); \
		(item) != NULL; \
		(item) = nes_queue_next_busy((queue), (item)))

#define NES_QUEUE_FOREACH_RETRY(item, queue) \
	for ((item) = nes_queue_first_busy_retry((queue)); \
		(item) != NULL; \
		(item) = nes_queue_next_busy_retry((queue), (item)))

typedef struct nes_queue_node_s {
	void              *data;
	struct nes_queue_node_s *next;
	rte_atomic16_t     busy;
	int                num;
} nes_queue_node_t;

typedef struct nes_queue_s {
	nes_queue_node_t *begin;
	nes_queue_node_t *end;
	rte_spinlock_t lock;
	int cnt;
} nes_queue_t;

/**
* Queue constructor. Should be used once per queue instance.
*
* @param[in,out] queue - queue instance
*/
void nes_queue_ctor(nes_queue_t *queue);
/**
* Queue destructor. Should be used once per queue instance.
*
* @param[in,out] queue - queue instance
*/
void nes_queue_dtor(nes_queue_t *queue);
/**
* Enqueue item at the end of the queue. It is multithread safe,
* both the queue and item contents are protected against race conditions.
*
* @param[in,out] queue - queue instance
* @param[in]     item  - the address of an item to be enqueued.
*                        MUST be permanent, the caller must take care of it.
* @return NES_SUCCESS on success, NES_FAIL if failed
*/
int  nes_queue_enqueue(nes_queue_t *queue, void *item);
/**
* Dequeue an item from the begining of the queue. It is multithread safe,
* the queue is protected against race conditions.
*
* @param[in,out] queue - queue instance
* @param[in,out] item  - the address of a dequeued item.
*                        The caller should probably free it after use.
* @return NES_SUCCESS on success, NES_FAIL if failed
*/
int  nes_queue_dequeue(nes_queue_t *queue, void **pitem);

/**
* Removes node from queue. It is multithread safe, the queue is protected against race conditions.
* The node contents is not freed, it is the caller's duty.
*
* @param[in,out] queue - queue instance
* @param[in,out] node  - the address of a dequeued node.
*                        The caller should take care of its contents.
* @return NES_SUCCESS on success, NES_FAIL if failed
*/
nes_queue_node_t *nes_queue_remove(nes_queue_t *queue, nes_queue_node_t *node);

/**
* Locks the queue node, making item this node carries unreachable for other tasks.
*
* @param[in,out] node  - the address of a node to be locked.
* @return NES_SUCCESS on success, NES_FAIL if failed
*/
static inline int nes_queue_node_lock(nes_queue_node_t *node)
{
	if (NULL == node)
		return NES_FAIL;

	return (1 == rte_atomic16_test_and_set(&node->busy) ?
		NES_SUCCESS :
		NES_FAIL);
}

/**
* Releases the queue node, making item this node carries reachable for other tasks.
*
* @param[in,out] node  - the address of a node to be unlocked.
* @return NES_SUCCESS on success, NES_FAIL if failed
*/
static inline int nes_queue_node_unlock(nes_queue_node_t *node)
{
	return (NULL != node ? rte_atomic16_clear(&node->busy),NES_SUCCESS : NES_FAIL);
}

/**
* Provides an address of a queue head to be used as an init value for an iterator.
* It does not attempt to lock a node, should be used with care.
*
* @param[in] queue - the queue instance
* @return queue head node address, NULL if queue is empty
*/
static inline nes_queue_node_t *nes_queue_first(nes_queue_t *queue)
{
	nes_queue_node_t *ret;
	rte_spinlock_lock(&(queue->lock));
	ret = queue->begin;
	rte_spinlock_unlock(&(queue->lock));
	return ret;
}

/**
* Provides an address of a queue head to be used as an init value for an iterator.
* It attempts to lock this node, and may fail.
*
* @param[in] queue - the queue instance
* @return queue head node address, NULL if queue is empty or head is locked by another task
*/
static inline nes_queue_node_t *nes_queue_first_busy(nes_queue_t *queueid)
{
	nes_queue_node_t *ret;
	rte_spinlock_lock(&(queueid->lock));
	ret = (NES_FAIL == nes_queue_node_lock(queueid->begin) ? NULL : queueid->begin);
	rte_spinlock_unlock(&(queueid->lock));
	return ret;
}

/**
* Provides an address of a queue head to be used as an init value for an iterator.
* It attempts to lock this node, and may fail.
* It attempts to lock node n times, n is defined by NES_QUEUE_RETRY
*
* @param[in] queue - the queue instance
* @return queue head node address, NULL if queue is empty or head is locked by another task
*/
static inline nes_queue_node_t *nes_queue_first_busy_retry(nes_queue_t *queueid)
{
	nes_queue_node_t *ret = NULL;
	int i;

	for (i = 0; i < NES_QUEUE_RETRY && ret == NULL; i++) {
		ret = nes_queue_first_busy(queueid);
		if (NULL == ret) usleep(1);
	}
	return ret;
}

/**
* Provides an address of a queue tail.
* It does not attempt to lock a node, should be used with care.
*
* @param[in] queue - the queue instance
* @return queue tail node address, NULL if queue is empty
*/
static inline nes_queue_node_t *nes_queue_last(nes_queue_t *queue)
{
	nes_queue_node_t *ret;
	rte_spinlock_lock(&(queue->lock));
	ret = queue->end;
	rte_spinlock_unlock(&(queue->lock));
	return ret;
}

/**
* Returns a number of queue nodes. This value may change right after it is returned.
*
* @param[in] queue - the queue instance
* @return queue head node address, NULL if queue is empty or head is locked by another task
*/
static inline int
nes_queue_node_size(nes_queue_t *queue)
{
	int ret;
	rte_spinlock_lock(&(queue->lock));
	ret = queue->cnt;
	rte_spinlock_unlock(&(queue->lock));
	return ret;
}

/**
* Returns an address of a successor of a given node in queue.
* Its purpose is to provide an increment to the queue iterator.
* It does not attempt to lock a node, should be used with care.
*
* @param[in] queue - the queue instance
* @param[in] node  - a node for which a successor is needed
* @return node's successor address, NULL if node is a queue tail
*/
static inline nes_queue_node_t *nes_queue_next(nes_queue_t *queue, nes_queue_node_t *node)
{
	nes_queue_node_t *ret;
	rte_spinlock_lock(&(queue->lock));
	ret = node->next;
	rte_spinlock_unlock(&(queue->lock));
	return ret;
}

/**
* Returns an address of a successor of a given node in queue.
* Its purpose is to provide an increment to the queue iterator.
* It unlocks a node and attempts to lock next node, thus it mail fail.
*
* @param[in]     queue - the queue instance
* @param[in,out] node  - a node for which a successor is needed
* @return node's successor address, NULL if node is a queue tail or locking next node failed
*/
static inline nes_queue_node_t *nes_queue_next_busy(nes_queue_t *queue, nes_queue_node_t *node)
{
	nes_queue_node_t *ret;
	rte_spinlock_lock(&(queue->lock));
	ret = (NES_FAIL == nes_queue_node_lock(node->next) ? NULL : node->next);
	nes_queue_node_unlock(node);
	rte_spinlock_unlock(&(queue->lock));
	return ret;
}

/**
* Returns an address of a successor of a given node in queue.
* Its purpose is to provide an increment to the queue iterator.
* It unlocks a node and attempts to lock next node, thus it mail fail.
* It attempts to lock node n times, where n is defined by NES_QUEUE_RETRY
*
* @param[in]     queue - the queue instance
* @param[in,out] node  - a node for which a successor is needed
* @return node's successor address, NULL if node is a queue tail or locking next node failed
*/
static inline nes_queue_node_t *
nes_queue_next_busy_retry(nes_queue_t *queue, nes_queue_node_t *node)
{
	nes_queue_node_t *ret = NULL;
	int i;
	for (i = 0 ; i < NES_QUEUE_RETRY && ret == NULL ; i++) {
		ret = nes_queue_next_busy(queue, node);
		if (NULL == ret) usleep(1);
	}
	return ret;
}

/**
* Returns an address of an item carried by the node.
*
* @param[in] node - the queue node
* @return an address of an item carried by the node
*/
static inline void *nes_queue_data(nes_queue_node_t *node)
{
	return node->data;
}

#ifdef __cplusplus
}
#endif /* extern "C" */

#endif /* _LIBNES_QUEUE_H_ */
