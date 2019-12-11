/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file libnes_queue.c
 * @brief Implementation of nes library for queues
 */

#include <assert.h>
#include <rte_config.h>
#include <rte_malloc.h>
#include "nes_common.h"
#include "libnes_queue.h"


void nes_queue_ctor(nes_queue_t *queue)
{
	assert(queue);
	queue->begin = NULL;
	queue->end   = NULL;
	rte_spinlock_init(&queue->lock);
	queue->cnt = 0;
}

void nes_queue_dtor(nes_queue_t *queue)
{
	nes_queue_node_t *node;
	void        *data;
	for (node = nes_queue_first(queue); node != NULL; node = nes_queue_next(queue,node))
		nes_queue_dequeue(queue,&data);
}

int nes_queue_enqueue(nes_queue_t *queue, void *data)
{
	nes_queue_node_t *result;
	assert(queue);
	result = rte_malloc(NULL, sizeof(*result), 0);
	if (NULL == result)
		return NES_FAIL;

	result->next = NULL;
	result->data = data;
	rte_atomic16_init(&result->busy);
	nes_queue_node_unlock(result);

	rte_spinlock_lock(&queue->lock);

	if (NULL == queue->begin)
		queue->begin = result;

	if (NULL != queue->end)
		queue->end->next = result;

	queue->end = result;
	queue->cnt++;

	rte_spinlock_unlock(&queue->lock);
	return NES_SUCCESS;
}

#define NES_QUEUE_MAX_DEQUEUE_ATTEMPTS 10

int  nes_queue_dequeue(nes_queue_t *queue, void **data)
{
	nes_queue_node_t *node;
	int i, ret = NES_FAIL;
	assert(queue);

	rte_spinlock_lock(&queue->lock);
	node = queue->begin;
	for (i = 0; i < NES_QUEUE_MAX_DEQUEUE_ATTEMPTS; i++) {
		if (NES_SUCCESS == nes_queue_node_lock(node)) {
			queue->begin = node->next;
			queue->cnt--;
			*data = node->data;
			rte_free(node);
			ret = NES_SUCCESS;
			break;
		}
	}
	rte_spinlock_unlock(&queue->lock);

	return ret;
}

nes_queue_node_t *nes_queue_remove(nes_queue_t *queueid, nes_queue_node_t *node)
{
	nes_queue_node_t *tmp_node, *prev_node;

	tmp_node = nes_queue_first_busy_retry(queueid);

	prev_node = NULL;
	while (tmp_node != NULL) {
		if (node == tmp_node) {
			if (prev_node != NULL) {
				prev_node->next = tmp_node->next;
				if (tmp_node == queueid->end)
					queueid->end = prev_node;

				nes_queue_node_unlock(prev_node);
			} else {
				if (tmp_node == queueid->begin) {
					queueid->begin = tmp_node->next;
					if (NULL == queueid->begin)
						queueid->end = NULL;
				}
			}

			queueid->cnt--;
			nes_queue_node_unlock(tmp_node);
			break;
		}
		if (prev_node != NULL)
			nes_queue_node_unlock(prev_node);
		prev_node = tmp_node;
		tmp_node = nes_queue_next_busy_retry(queueid, prev_node);
	}

	return tmp_node;
}
