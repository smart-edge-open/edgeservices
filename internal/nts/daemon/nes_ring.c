/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_ring.c
 * @brief Implementation of methods defined in header file
 */

#include <string.h>
#include <rte_ring.h>
#include <rte_lcore.h>
#include "nes_common.h"
#include "libnes_cfgfile.h"
#include "nes_ring.h"
#include "nes_ring_lookup.h"
#include "nts/nts_edit.h"
#include "nts/nts_io.h"
#include "io/nes_dev.h"
#include "ctrl/nes_ctrl.h"

#ifdef UNIT_TESTS
	#include "nes_ring_decl.h"
#endif

#define VM_RX_QUEUE_NAME_TEMPLATE "NTS_VM%d_ANY"
#define VM_TX_QUEUE_NAME_TEMPLATE "IO_VM%d_ANY"
#define KNI_RX_QUEUE_NAME_TEMPLATE "NTS_KNI%d_ANY"
#define KNI_TX_QUEUE_NAME_TEMPLATE "IO_KNI%d_ANY"
#define PORT_TX_QUEUE_NAME_TEMPLATE "PORT_%d_IO_ANY"

static nes_ring_params_t nes_ring_params_table[] = {
	/* name,           count,                     multiproducer, threshold_us */
	{ "NIS_UPSTR_GTPUC", NES_RING_ELEMENTS_DEFAULT, NO,            100},
	{ "NIS_UPSTR_GTPC",  NES_RING_ELEMENTS_DEFAULT, NO,            100},
	{ "NIS_UPSTR_RNIS",  NES_RING_ELEMENTS_DEFAULT, NO,            100},
	{ "NIS_UPSTR_SCTP",  NES_RING_ELEMENTS_DEFAULT, NO,            100},

	{ "NIS_DWSTR_GTPUC", NES_RING_ELEMENTS_DEFAULT, NO,            100},
	{ "NIS_DWSTR_GTPC",  NES_RING_ELEMENTS_DEFAULT, NO,            100},
	{ "NIS_DWSTR_RNIS",  NES_RING_ELEMENTS_DEFAULT, NO,            100},
	{ "NIS_DWSTR_SCTP",  NES_RING_ELEMENTS_DEFAULT, NO,            100},

	{ "NTS_UPSTR_GTPU",  NES_RING_ELEMENTS_DEFAULT, NO,             10},
	{ "NTS_DWSTR_GTPU",  NES_RING_ELEMENTS_DEFAULT, NO,             10},

	/* pure IP rings */
	{ "NTS_UPSTR_IP",    NES_RING_ELEMENTS_DEFAULT, NO,            10},
	{ "NTS_DWSTR_IP",    NES_RING_ELEMENTS_DEFAULT, NO,            10},

	{ LBP_RX_RING_NAME,  NES_RING_ELEMENTS_DEFAULT, NO,             10},

	{ AVP_RX_RING_NAME,  NES_RING_ELEMENTS_DEFAULT, NO,             10},
	{ AVP_TX_RING_NAME,  NES_RING_ELEMENTS_DEFAULT, NO,             10},
	/* The last one */
	{ NULL,            NES_RING_ELEMENTS_DEFAULT, NO,            100}
};

nes_ring_params_t *nes_ring_params_table_get(void)
{
	return nes_ring_params_table;
}

int nes_ring_norings(void)
{
	nes_ring_params_t *nes_ring_params_table = nes_ring_params_table_get();
	int i;
	for (i = 0; nes_ring_params_table[i].name != NULL; i++)
		;
	i += count_port_devices();
	return i;
}

NES_STATIC int nes_ring_set_flow(nes_ring_t *self)
{
	int retval = NES_SUCCESS;
	const char *name = nes_ring_name(self);
	self->flow = NULL;
	if (0 == strncmp("NTS",name,3))
		retval = nts_edit_ring_flow_set(self);

	return retval;
}

NES_STATIC int nes_ring_ctor(nes_ring_t *self, void *arg)
{
	nes_ring_params_t *params = arg;
	unsigned ring_flags;
	self->remove = 0;

	/* All rings are single consumer */
	ring_flags  = RING_F_SC_DEQ;
	ring_flags |= (NO == params->multiproducer ? RING_F_SP_ENQ : 0x0000);
	self->ring = rte_ring_create(params->name, params->count, rte_socket_id(), ring_flags);
	if (NULL == self->ring) {
		NES_LOG(ERR,"Could not create a ring %s.\n",params->name);
		return NES_FAIL;
	}
	/* Should be done in instantiation but here it */
	nes_ring_set_flow(self);
	self->routing_tables = nts_io_routing_tables_get();

	nes_ctrl_ring_t *ring_stats;
	ring_stats = rte_zmalloc(NULL, sizeof(nes_ctrl_ring_t), 0);
	if (NULL == ring_stats) {
		NES_LOG(ERR,"Could not allocate memory for ring stats.\n");
		return NES_FAIL;
	}
	strncpy(ring_stats->name, self->ring->name, sizeof(ring_stats->name) - 1);

	NES_STATS_INIT_RING(ring_stats);

	self->ring_stats = ring_stats;
	nes_ctrl_add_ring(self, self->ring->name);

	return NES_SUCCESS;
}

NES_STATIC int
nes_ring_dtor(__attribute__((unused)) nes_ring_t *self, __attribute__((unused)) void *data)
{
	return NES_SUCCESS;
}

NES_STATIC int nes_ring_enq_sp(nes_ring_t *self, void *buffer)
{
	/* A single producer enqueue call */
	int retval = rte_ring_sp_enqueue(self->ring,buffer);
	if (0 == retval) {
		NES_STATS_RING_UPDATE(1, self->ring_stats->stats.snd_cnt);
		return NES_SUCCESS;
	}
	NES_STATS_RING_UPDATE(1, self->ring_stats->stats.drp_cnt_1);
	return NES_FAIL;
}

NES_STATIC int nes_ring_enq_burst_sp(nes_ring_t *self, void **buffer, int count)
{
	int i, burst_size, next_burst;
	next_burst = NES_RING_BURST_SIZE;
	for (i = 0; i < count; i += NES_RING_BURST_SIZE) {
		int burst;

		burst_size  = count > next_burst ? NES_RING_BURST_SIZE : count - i;
		next_burst += MAX_BURST_SIZE;

		/* A single producer enqueue call */
		burst = rte_ring_sp_enqueue_burst(self->ring, &buffer[i], burst_size, NULL);
		NES_STATS_RING_UPDATE(burst, self->ring_stats->stats.snd_cnt);
		if (burst < burst_size) {
			NES_STATS_RING_UPDATE(burst_size - burst,
				self->ring_stats->stats.drp_cnt_1);
			return i + burst;
		}
	}
	return count;
}

NES_STATIC int nes_ring_enq_mp(nes_ring_t *self, void *buffer)
{
	/* A multi producer enqueue call */
	int retval = rte_ring_mp_enqueue(self->ring,buffer);
	if (0 == retval) {
		NES_STATS_RING_UPDATE(1, self->ring_stats->stats.snd_cnt);
		return NES_SUCCESS;
	}
	NES_STATS_RING_UPDATE(1, self->ring_stats->stats.drp_cnt_1);
	return NES_FAIL;
}

NES_STATIC int nes_ring_enq_burst_mp(nes_ring_t *self, void **buffer, int count)
{
	int i, burst_size, next_burst;
	next_burst = NES_RING_BURST_SIZE;
	for (i = 0; i < count; i += NES_RING_BURST_SIZE) {
		int burst;

		burst_size  = count > next_burst ? NES_RING_BURST_SIZE : count - i;
		next_burst += MAX_BURST_SIZE;

		/* A multi producer enqueue call */
		burst = rte_ring_mp_enqueue_burst(self->ring, &buffer[i], burst_size, NULL);
		NES_STATS_RING_UPDATE(burst, self->ring_stats->stats.snd_cnt);

		if (burst < burst_size) {
			NES_STATS_RING_UPDATE(burst_size - burst,
				self->ring_stats->stats.drp_cnt_1);
			return i + burst;
		}
	}
	return count;
}
NES_STATIC int nes_ring_deq_burst_sc(nes_ring_t *self, void **buffer, int count)
{
	int i, burst_size, next_burst;
	next_burst = NES_RING_BURST_SIZE;
	for (i = 0; i < count; i += NES_RING_BURST_SIZE) {
		int burst;

		burst_size  = count > next_burst ? NES_RING_BURST_SIZE : count - i;
		next_burst += MAX_BURST_SIZE;

		/* A single consumer dequeue call */
		burst = rte_ring_sc_dequeue_burst(self->ring, &buffer[i], burst_size, NULL);
		NES_STATS_RING_UPDATE(burst, self->ring_stats->stats.rcv_cnt);
		if (burst < burst_size)
			return i + burst;
	}
	return count;
}

NES_STATIC int nes_ring_deq_sc(nes_ring_t *self, void **buffer)
{
	unsigned retval;
	/* A single consumer dequeue call */
	retval = rte_ring_sc_dequeue(self->ring,buffer);
	if (0 == retval) {
		NES_STATS_RING_UPDATE(1, self->ring_stats->stats.rcv_cnt);
		return NES_SUCCESS;
	}
	return NES_FAIL;
}

NES_STATIC int nes_ring_instantiate(nes_ring_t **newring, nes_ring_params_t *params)
{
	/* Instantiate and write into lookup table */
	if (NES_FAIL == nes_ring_lookup_entry_get(params->name,newring)) {
		NES_LOG(ERR,"Could not create an instance of %s.\n",params->name);
		return NES_FAIL;
	}

	(*newring)->ctor = nes_ring_ctor;
	(*newring)->dtor = nes_ring_dtor;
	(*newring)->deq       =  nes_ring_deq_sc;
	(*newring)->deq_burst =  nes_ring_deq_burst_sc;
	(*newring)->enq       = (YES == params->multiproducer ?
		nes_ring_enq_mp : nes_ring_enq_sp);
	(*newring)->enq_burst = (YES == params->multiproducer ?
		nes_ring_enq_burst_mp : nes_ring_enq_burst_sp);

	return NES_SUCCESS;
}

int nes_ring_init(void)
{
	int i;
	nes_ring_t *newring;

	if (NES_FAIL == nes_ring_lookup_init())
		return NES_FAIL;

	if (NES_FAIL == nes_ctrl_ctor_ring_list()) {
		NES_LOG(ERR,"Can't create rings list.\n");
		return NES_FAIL;
	}

	for (i = 0; nes_ring_params_table[i].name != NULL; i++) {
		/* Avoid creating LBP rings if [LBP] config section is missing */
		if (0 == strncmp(nes_ring_params_table[i].name, LBP_RX_RING_NAME,
				NES_RING_NAME_LEN)) {
			if (NES_FAIL == is_lbp_enabled())
				continue;

		}
		/* Avoid creating AVP rings if there is no AVP port */
		if (0 == strncmp(nes_ring_params_table[i].name, AVP_RX_RING_NAME,
				NES_RING_NAME_LEN) || 0 == strncmp(nes_ring_params_table[i].name,
					AVP_TX_RING_NAME, NES_RING_NAME_LEN)) {
			if (NES_FAIL == is_avp_enabled())
				continue;

		}

		/* Instantiate */
		if (NES_FAIL == nes_ring_instantiate(&newring, &nes_ring_params_table[i]))
			return NES_FAIL;

		/* Run the constructor */
		if (NES_FAIL == newring->ctor(newring, &nes_ring_params_table[i]))
			return NES_FAIL;
	} /* for (i = 0; nes_ring_params_table[i].name != NULL; i++) */
	return NES_SUCCESS;
}

static int
nes_ring_pair_set(int id, nes_ring_t **rx_ring_ptr, nes_ring_t **tx_ring_ptr,
	uint8_t is_kni)
{
	char buffer[NES_RING_NAME_LEN];
	char *ptr;
	nes_ring_params_t ring_params = {
		.count = NES_RING_ELEMENTS_DEFAULT,
		.multiproducer = NO,
		.threshold_us  = 10,
	};

	if (is_kni)
		snprintf(buffer, sizeof(buffer), KNI_RX_QUEUE_NAME_TEMPLATE, id);
	else
		snprintf(buffer, sizeof(buffer), VM_RX_QUEUE_NAME_TEMPLATE, id);

	if (NES_FAIL == nes_ring_find(rx_ring_ptr, buffer)) {
		ring_params.name = buffer;
		if (NES_FAIL == nes_ring_instantiate(rx_ring_ptr, &ring_params))
			return NES_FAIL;
		if (NES_FAIL == (*rx_ring_ptr)->ctor(*rx_ring_ptr,&ring_params))
			return NES_FAIL;
	}

	if (is_kni)
		ptr = nts_lookup_tx_kni_ring_name_get(id);
	else
		ptr = nts_lookup_tx_vm_ring_name_get(id);

	if (ptr == NULL)
		return NES_FAIL;

	if (NES_FAIL == nes_ring_find(tx_ring_ptr, ptr)) {
		ring_params.name = ptr;
		if (NES_FAIL == nes_ring_instantiate(tx_ring_ptr, &ring_params))
			return NES_FAIL;

		if (NES_FAIL == (*tx_ring_ptr)->ctor(*tx_ring_ptr,&ring_params))
			return NES_FAIL;
	}
	return NES_SUCCESS;
}

int nes_ring_per_vm_set(int vm_id, nes_ring_t **rx_ring_ptr, nes_ring_t **tx_ring_ptr)
{
	return nes_ring_pair_set(vm_id, rx_ring_ptr, tx_ring_ptr, 0);
}

int nes_ring_per_kni_set(int vm_id, nes_ring_t **rx_ring_ptr, nes_ring_t **tx_ring_ptr)
{
	return nes_ring_pair_set(vm_id, rx_ring_ptr, tx_ring_ptr, 1);
}

int nes_ring_per_port_set(int port_id, nes_ring_t **tx_ring_ptr)
{
	char buffer[NES_RING_NAME_LEN];
	nes_ring_params_t ring_params = {
		.count = NES_RING_ELEMENTS_DEFAULT,
		.multiproducer = YES,
		.threshold_us  = 10,
	};

	if (count_port_devices() <= port_id)
		return NES_FAIL;

	snprintf(buffer, sizeof(buffer), PORT_TX_QUEUE_NAME_TEMPLATE, port_id);
	if (NES_FAIL == nes_ring_find(tx_ring_ptr, buffer)) {
		ring_params.name = buffer;
		if (NES_FAIL == nes_ring_instantiate(tx_ring_ptr, &ring_params))
			return NES_FAIL;
		if (NES_FAIL == (*tx_ring_ptr)->ctor(*tx_ring_ptr, &ring_params))
			return NES_FAIL;
	}
	return NES_SUCCESS;
}
