/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <rte_errno.h>
#include "test_nis_io.h"
#include "nes_common.h"
#include "nis/nis_io.h"
#include "io/nes_io.h"
#include "nis_io_decl.h"
#include "libnes_cfgfile.h"
#include "nes_ring_lookup.h"
#include "nes_ring_lookup_decl.h"
#include "test_nes_ring_lookup.h"
#include "libnes_cfgfile_def.h"

static struct rte_cfgfile_section section_VM_common = {
	.name = "VM common"
};

static struct rte_cfgfile_entry  entry_max = {
	.name = "max", .value = "5"
};

struct rte_cfgfile *cfg_bak;
pthread_t nis_io_main_thread;

extern struct rte_cfgfile *nes_cfgfile;
extern nes_lookup_table_t nes_ring_lookup_table;

#define CFG_ALLOC_SECTION_BATCH 8

MOCK_INIT(mocked_nes_queue_enqueue);

int init_suite_nis_io(void) {
	cfg_bak = nes_cfgfile;
	nes_cfgfile = malloc(sizeof (*nes_cfgfile));

	if (!nes_cfgfile)
		return CUE_NOMEMORY;

	section_VM_common.entries = &entry_max;
	nes_cfgfile->sections = &section_VM_common;
	nes_cfgfile->sections[0] = section_VM_common;
	nes_cfgfile->sections[0].num_entries = 1;

	nes_cfgfile->num_sections = 1;
	rte_atomic32_clear(&threads_started);
	MOCK_RESET(mocked_nes_queue_enqueue);
	return CUE_SUCCESS;
}

int cleanup_suite_nis_io(void) {
	free(nes_cfgfile);
	nes_cfgfile = cfg_bak;
	nes_thread_terminate = 0;
	rte_atomic32_clear(&threads_started);
	MOCK_RESET(mocked_nes_queue_enqueue);
	return CUE_SUCCESS;
}

static void *nis_io_main_thread_start(void *arg) {
	(void)arg;
	nis_io_main(NULL);
	return NULL;
}

static struct nes_rings_bak_s nes_rings_tab[] = {
	{ "NIS_UPSTR_RNIS", NULL },
	{ "NIS_UPSTR_SCTP", NULL },
	{ "NIS_UPSTR_GTPUC", NULL },
	{ "NIS_UPSTR_GTPC", NULL },
	{ "NIS_DWSTR_RNIS", NULL },
	{ "NIS_DWSTR_SCTP", NULL },
	{ "NIS_DWSTR_GTPUC", NULL },
	{ "NIS_DWSTR_GTPC", NULL },
};

static int nes_queue_enqueue_fake_fail(nes_queue_t *queue, void *data) {
	(void)queue;
	(void)data;
	return NES_FAIL;
}

static void nis_io_init_traffic_rings_test(void) {
	CU_ASSERT_EQUAL(nis_io_init_traffic_rings(), NES_SUCCESS);
	size_t i;
	for (i = 0; i < sizeof(nes_rings_tab)/sizeof(nes_rings_tab[0]); i++) {
		if (NES_SUCCESS == nes_ring_find(&nes_rings_tab[i].ring, nes_rings_tab[i].name)) {
			nes_ring_del(nes_rings_tab[i].name);
			CU_ASSERT_EQUAL(nis_io_init_traffic_rings(), NES_FAIL);
			nes_ring_add(nes_rings_tab[i].name, nes_rings_tab[i].ring);
		}
	}

	CU_ASSERT_EQUAL(nis_io_init_traffic_rings(), NES_SUCCESS);
	MOCK_SET(mocked_nes_queue_enqueue, nes_queue_enqueue_fake_fail);
	CU_ASSERT_EQUAL(nis_io_init_traffic_rings(), NES_FAIL);
	MOCK_RESET(mocked_nes_queue_enqueue);
}

#define RINGNAME "NIS_UPSTR_RNIS"

static void nis_io_init_flows_test(void) {
	int (*flow_bak)(struct nes_ring_s *, void **, int);
	nes_ring_t *ring_bak;

	CU_ASSERT_EQUAL(nis_io_init_traffic_rings(), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_io_init_flows(), NES_SUCCESS);
	nes_ring_find(&ring_bak, RINGNAME);

	CU_ASSERT_PTR_NOT_NULL_FATAL(ring_bak);

	flow_bak = ring_bak->flow;
	ring_bak->flow = NULL;
	strcpy(ring_bak->ring->name, "test");
	CU_ASSERT_EQUAL(nis_io_init_flows(), NES_FAIL);
	strcpy(ring_bak->ring->name, RINGNAME);
	ring_bak->flow = flow_bak;
	CU_ASSERT_EQUAL(nis_io_init_flows(), NES_SUCCESS);
}

static void nis_io_init_test(void) {
	nes_ring_t *ring_bak;
	CU_ASSERT_EQUAL(nis_io_init(), NES_SUCCESS);
	if (NES_SUCCESS == nes_ring_find(&ring_bak, RINGNAME)) {
		nes_ring_del(RINGNAME);
		CU_ASSERT_EQUAL(nis_io_init(), NES_FAIL);
		nes_ring_add(RINGNAME, ring_bak);
	}
}

static void nis_io_main_test(void) {
	void *res;
	nes_ring_t *ring;
	int (*deq_burst_bak)(struct nes_ring_s *, void **, int);
	nes_thread_terminate = 1;
	CU_ASSERT_EQUAL(nis_io_main(NULL), NES_SUCCESS);
	rte_atomic32_clear(&threads_started);

	nes_thread_terminate = 0;
	pthread_create(&nis_io_main_thread, NULL, nis_io_main_thread_start, NULL);
	while (!(THREAD_NIS_IO_ID & rte_atomic32_read(&threads_started)))
		usleep(1);

#define nes_ring_burst_size_sp 64
	int *data[nes_ring_burst_size_sp] = {NULL};

	nes_ring_find(&ring, "NIS_DWSTR_RNIS");

	CU_ASSERT_PTR_NOT_NULL_FATAL(ring);

	ring->enq(ring, (void**) data);
	nes_ring_find(&ring, RINGNAME);
	ring->enq(ring, (void**) data);
	deq_burst_bak = ring->deq_burst;
	usleep(100000);
	ring->deq_burst = NULL;
	usleep(1000);
	ring->deq_burst = deq_burst_bak;
	nes_thread_terminate = 1;
	pthread_cancel(nis_io_main_thread);
	pthread_join(nis_io_main_thread, &res);
	nes_thread_terminate = 1;
	nes_ring_t *ring_bak;
	if (NES_SUCCESS == nes_ring_find(&ring_bak, RINGNAME)) {
		nes_ring_del(RINGNAME);
		CU_ASSERT_EQUAL(nis_io_main(NULL), NES_FAIL);
		nes_ring_add(RINGNAME, ring_bak);
	}
	nes_thread_terminate = 0;
}

void add_nis_io_suite_to_registry(void) {
	CU_pSuite nis_io_suite = CU_add_suite("nis_io", init_suite_nis_io, cleanup_suite_nis_io);

	CU_add_test(nis_io_suite, "nis_io_main", nis_io_main_test);
	CU_add_test(nis_io_suite, "nis_io_init_traffic_rings", nis_io_init_traffic_rings_test);
	CU_add_test(nis_io_suite, "nis_io_init_flows", nis_io_init_flows_test);
	CU_add_test(nis_io_suite, "nis_io_init", nis_io_init_test);
}

