/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file libnes_sq.c
 * @brief Implementation of nes library for queues
 */

#include <assert.h>

#ifdef LIBNES_API
	#include <stdlib.h>
#else
	#include <rte_malloc.h>
#endif
#include "nes_common.h"
#include "libnes_sq.h"

#ifdef LIBNES_API
	#define  nes_malloc(size) malloc((size))
	#define  nes_free(ptr) free((ptr))
#else
	#define  nes_malloc(size) rte_malloc(NULL,(size),0);
	#define  nes_free(ptr) rte_free((ptr))
#endif

void nes_sq_ctor(nes_sq_t *queue)
{
	assert(queue);
	queue->head = NULL;
	queue->tail = NULL;
	queue->cnt = 0;
}

void nes_sq_dtor(nes_sq_t *queue)
{
	nes_sq_node_t *node;
	void          *data;
	NES_SQ_FOREACH(node,queue) {
		nes_sq_deq(queue,&data);
	}
}

void nes_sq_dtor_free(nes_sq_t *queue)
{
	nes_sq_node_t *node;
	void          *data;
	NES_SQ_FOREACH(node,queue) {
		nes_sq_deq(queue,&data);
		nes_free(data);
	}
}

int nes_sq_enq(nes_sq_t *queue, void *data)
{
	nes_sq_node_t *newnode;

	assert(queue);
	newnode = nes_malloc(sizeof(*newnode));
	if (NULL == newnode)
		return NES_FAIL;

	newnode->next = NULL;
	newnode->data = data;

	if (NULL == queue->head)
		queue->head = newnode;

	if (NULL != queue->tail)
		queue->tail->next = newnode;

	queue->tail = newnode;
	queue->cnt++;

	return NES_SUCCESS;
}

int nes_sq_deq(nes_sq_t *queue, void **data)
{
	nes_sq_node_t *node;
	int retval;

	assert(queue);
	node = queue->head;
	if (NULL != node) {
		*data = node->data;
		queue->head = node->next;
		queue->cnt--;
		nes_free(node);
		retval = NES_SUCCESS;
	} else {
		*data = NULL;
		retval = NES_FAIL;
	}
	if (NULL == queue->head)
		queue->tail = NULL;

	return retval;
}

nes_sq_node_t *nes_sq_get(nes_sq_t *queue, uint16_t index)
{
	int i;
	nes_sq_node_t *item;

	item = nes_sq_head(queue);

	for (i = 0; i < index; i++) {
		if (NULL == item)
			return NULL;

		item = item->next;
	}

	return item;
}

void nes_sq_remove(nes_sq_t *queue, nes_sq_node_t *node)
{
	nes_sq_node_t *item;
	assert(queue);
	assert(node);

	if (queue->head == node) {
		queue->head = node->next;
		if (queue->tail == node)
			queue->tail = NULL;

		nes_free(node);
		queue->cnt--;
	}
	else {
		NES_SQ_FOREACH(item,queue) {
			if (item->next == node || item == node) {
				item->next = item->next->next;
				if (NULL == item->next)
					queue->tail = item;

				nes_free(node);
				queue->cnt--;
				break;
			}
		}
	}
}
