/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_latency.h
 * @brief Header file for nes_latency
 */

#ifndef NES_LATENCY_H
#define	NES_LATENCY_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <limits.h>
#include <inttypes.h>

#include <rte_atomic.h>
#include <rte_cycles.h>

#define LATENCY_STATS_FILE_PATH "/root/stats.csv"
#define PRINT_LATENCY_STATS_DELAY_MS 1000
#define MAX_LATENCY_ID UINT8_MAX
#define RTT_TIMESTAMP_OFFSET 100

#ifndef NES_LATENCY
	#define NES_LATENCY_READ_TIMESTAMP(timestamp_name)
	#define NES_LATENCY_INSERT_TIMESTAMPS(pkts, pkts_cnt, t_start)
	#define NES_LATENCY_GET_TIMESTAMPS(pkts, pkts_cnt, pkt_stats)
	#define NES_LATENCY_UPDATE(pkts_cnt, pkt_stats, t_end)
	#define NES_LATENCY_START_THREAD(core_id)
	#define NES_LATENCY_VARS
#else
	#define NES_LATENCY_READ_TIMESTAMP(timestamp_name) \
		volatile uint64_t (timestamp_name) = rte_rdtsc_precise()

	#define NES_LATENCY_INSERT_TIMESTAMPS(pkts, pkts_cnt, t_start) \
		do { \
			int i; \
			struct timestamp_s *pkt_timestamp; \
			for (i = 0; i < (pkts_cnt); ++i) { \
				pkt_timestamp = (struct timestamp_s *) \
					(rte_pktmbuf_mtod((pkts)[i], uint8_t*) + \
					RTT_TIMESTAMP_OFFSET); \
				pkt_timestamp->timestamp = (t_start); \
			} \
		} while (0)

	#define NES_LATENCY_GET_TIMESTAMPS(pkts, pkts_cnt, pkt_stats) \
		struct timestamp_s pkt_timestamps[MAX_BURST_SIZE]; \
		do { \
			int i; \
			for (i = 0; i < (pkts_cnt); ++i) { \
				if (rte_pktmbuf_data_len((pkts)[i]) < \
						RTT_TIMESTAMP_OFFSET + sizeof((pkt_stats)[0])) { \
					NES_LOG(ERR, "NES_LATENCY: To small packet!! size %d\n", \
						rte_pktmbuf_data_len((pkts)[i])); \
				} \
				(pkt_stats)[i] = *(struct timestamp_s *) \
					(rte_pktmbuf_mtod((pkts)[i], uint8_t*) + \
					 RTT_TIMESTAMP_OFFSET); \
			} \
		} while (0)

	#define NES_LATENCY_UPDATE(pkts_cnt, pkt_stats, t_end) \
		do { \
			int i; \
			volatile uint64_t elapsed; \
			for (i = 0; i < (pkts_cnt); ++i) { \
				elapsed = (t_end) - (pkt_stats)[i].timestamp; \
				++latency_stats.pkts; \
				latency_stats.total += elapsed; \
				if (unlikely(latency_stats.min > elapsed)) { \
					latency_stats.min = elapsed; \
				} \
				if (unlikely(latency_stats.max < elapsed)) { \
					latency_stats.max = elapsed; \
				} \
			} \
			if (rte_atomic16_read(&reset_stats)) { \
				rte_atomic16_set(&reset_stats, 0); \
				latency_stats.min = UINT64_MAX; \
				latency_stats.max = 0; \
				latency_stats.total = 0; \
				latency_stats.pkts = 0; \
			} \
		} while (0)

	#define NES_LATENCY_START_THREAD(core_id) \
		rte_eal_remote_launch(nes_latency_main, NULL, (core_id))


	struct timestamp_s {
		uint64_t timestamp;
	};
	struct latency_stats_s {
		uint64_t min;
		uint64_t max;
		uint64_t total;
		uint64_t pkts;
	};

	int nes_latency_main(__attribute__((unused))void *arg);

	#define NES_LATENCY_VARS \
		rte_atomic16_t reset_stats; \
		struct latency_stats_s latency_stats = \
			{ .min = UINT64_MAX, .max = 0, .total = 0, .pkts = 0}
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* NES_LATENCY_H */
