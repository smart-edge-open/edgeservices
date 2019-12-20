/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file libnes_sq.h
 * @brief Header file for NES simple queue library
 */

#ifndef _LIBNES_SQ_H_
#define _LIBNES_SQ_H_

#ifdef __cplusplus
extern "C" {
#endif

#define NES_SQ_FOREACH(item, queue) \
	for ((item) = nes_sq_head((queue)); \
			(item) != NULL; \
			(item) = nes_sq_next((item)))

typedef struct nes_sq_node_s {
	void                 *data;
	struct nes_sq_node_s *next;
} nes_sq_node_t;

typedef struct nes_sq_s {
	nes_sq_node_t *head;
	nes_sq_node_t *tail;
	int cnt;
} nes_sq_t;

/**
* Queue constructor. Should be used once per queue instance.
*
* @param[in,out] queue - queue instance
*/
void nes_sq_ctor(nes_sq_t *queue);

/**
* Queue destructor. Should be used once per queue instance.
*
* @param[in,out] queue - queue instance
*/
void nes_sq_dtor(nes_sq_t *queue);

/**
* Queue destructor. Should be used once per queue instance.
* Tries to free every element
*
* @param[in,out] queue - queue instance
*/
void nes_sq_dtor_free(nes_sq_t *queue);

/**
* Enqueue item at the end of the queue.
*
* @param[in,out] queue - queue instance
* @param[in]     item  - the address of an item to be enqueued.
*                        MUST be permanent, the caller must take care of it.
* @return NES_SUCCESS on success, NES_FAIL if failed
*/
int  nes_sq_enq(nes_sq_t *queue, void *item);

/**
* Dequeue an item from the beginning of the queue.
*
* @param[in,out] queue - queue instance
* @param[in,out] pitem - the address of a dequeued item.
*                        The caller should probably free it after use.
* @return NES_SUCCESS on success, NES_FAIL if failed
*/
int nes_sq_deq(nes_sq_t *queue, void **pitem);

/**
 * Find queue node.
 *
 * @param[in] queue - queue instance
 * @param[in] index - index of wanted node
 *
 * @return pointer to the node
 * */
nes_sq_node_t *nes_sq_get(nes_sq_t *queue, uint16_t index);

/**
* Removes node from queue. It is multithread safe, the queue is protected against race conditions.
* The node contents is not freed, it is the caller's duty.
*
* @param[in,out] queue - queue instance
* @param[in,out] node  - the address of a dequeued node.
*                        The caller should take care of its contents.
*/
void nes_sq_remove(nes_sq_t *queue, nes_sq_node_t *node);

/**
* Provides an address of a queue head to be used as an init value for an iterator.
*
* @param[in] queue - the queue instance
* @return queue head node address, NULL if queue is empty
*/
static inline nes_sq_node_t *nes_sq_head(nes_sq_t *queue)
{
	return NULL == queue ? NULL : queue->head;
}

/**
* Provides an address of a queue tail.
*
* @param[in] queue - the queue instance
* @return queue tail node address, NULL if queue is empty
*/
static inline nes_sq_node_t *nes_sq_tail(nes_sq_t *queue)
{
	return NULL == queue ? NULL : queue->tail;
}

/**
* Returns a number of queue nodes. This value may change right after it is returned.
*
* @param[in] queue - the queue instance
* @return queue head node address, NULL if queue is empty or head is locked by another task
*/
static inline int nes_sq_len(nes_sq_t *queue)
{
	return NULL == queue ? -1 : queue->cnt;
}

/**
* Returns an address of a successor of a given node in queue.
* Its purpose is to provide an increment to the queue iterator.
* It does not attempt to lock a node, should be used with care.
*
* @param[in] node  a node for which a successor is needed
* @return node's successor address, NULL if node is a queue tail
*/
static inline nes_sq_node_t *nes_sq_next(nes_sq_node_t *node)
{
	return NULL == node ? NULL : node->next;
}

/**
* Returns an address of an item carried by the node.
*
* @param[in] node - the queue node
* @return an address of an item carried by the node
*/
static inline void *nes_sq_data(nes_sq_node_t *node)
{
	return NULL == node ? NULL : node->data;
}

#ifdef __cplusplus
}
#endif /* extern "C" */

#endif /* _LIBNES_SQ_H_ */
