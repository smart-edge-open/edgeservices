/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_latency.c
 * @brief implementation of nes_latency
 */

#include "nes_latency.h"
#include "nes_common.h"

#ifdef NES_LATENCY
static FILE* stats_file;

extern struct latency_stats_s latency_stats;
extern rte_atomic16_t reset_stats;

static void
print_stats(void) {
	if (NULL == stats_file)
		return;

	static double cpu_freq = 0;
	if (0 == cpu_freq)
		cpu_freq = rte_get_tsc_hz() / 1E6;
	fprintf(stats_file, "%.03f,%.03f,%.03f,%"PRIu64"\n",
		latency_stats.min / cpu_freq,
		(latency_stats.total / latency_stats.pkts) / cpu_freq,
		latency_stats.max / cpu_freq,
		latency_stats.pkts);
	fflush(stats_file);
}

int
nes_latency_main(__attribute__((unused))void *arg) {
	stats_file = fopen(LATENCY_STATS_FILE_PATH, "w+");
	if (NULL == stats_file)
		NES_LOG(ERR, "Failed to open %s, stats won't be saved!\n", LATENCY_STATS_FILE_PATH);

	fprintf(stats_file, "Min[us],Avg[us],Max[us],Pkts,Check interval: %d ms\n",
		PRINT_LATENCY_STATS_DELAY_MS);
	NES_LOG(INFO, "nes_latency_main started\n");
	while (1) {
		if (latency_stats.pkts)
			print_stats();

		rte_atomic16_set(&reset_stats, 1);
		rte_delay_ms(PRINT_LATENCY_STATS_DELAY_MS);
	}
	return 0;
}
#endif
