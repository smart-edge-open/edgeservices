/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_ctrl.h
 * @brief Header file for nes control
 */

#ifndef _NES_CTRL_H_
#define _NES_CTRL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/un.h>

#include "nes_common.h"
#include "nts/nts_edit.h"
#include "nts/nts_lookup.h"
#include "libnes_queue.h"

#include "libnes_sq.h"
#include "libnes_api_protocol.h"

#ifdef DSTATS
/**
 * Marks statistics specific declarations.
 */
#define NES_STATS_DECL
/**
 * Assign (x) = (y); only if DSTATS is defined.
 * Run (y); otherwise.
 */
#define NES_STATS_ASSGN(x,y) (x)=(y)
/**
 * Initialize per device statistics only if DSTATS is defined.
 */
#define NES_STATS_INIT_DEV(device) do { \
		(device)->stats.rcv_cnt = 0;        \
		(device)->stats.snd_cnt = 0;        \
		(device)->stats.drp_cnt_1 = 0;      \
		(device)->stats.drp_cnt_2 = 0;      \
		(device)->stats.rcv_bytes = 0;      \
		(device)->stats.snd_bytes = 0;      \
		(device)->stats.drp_bytes_1 = 0;    \
		(device)->stats.ip_fragment = 0;    \
	} while(0)
/**
 * Update counter only if DSTATS is defined.
 */
#define NES_STATS_DEV_UPDATE(number, cnt) do { \
		(cnt) += (number);             \
	} while(0)

#ifdef RSTATS
/**
 * Initialize per ring statistics only if DSTATS is defined.
 */
#define NES_STATS_INIT_RING(ring) do {            \
		(ring)->stats.rcv_cnt = 0;        \
		(ring)->stats.snd_cnt = 0;        \
		(ring)->stats.drp_cnt_1 = 0;      \
		(ring)->stats.drp_cnt_2 = 0;      \
	} while(0)

/**
 * Update counter only if DSTATS and RSTATS is defined.
 */
#define NES_STATS_RING_UPDATE(number, cnt) do { \
		(cnt) += (number);              \
	} while(0)

/**
 * Read per ring statistics only if DSTATS is defined.
 */
#define NES_STATS_GET_PACKETS_RING(ring, rcv, snd, drp_1, drp_2) do { \
		rcv = (ring)->stats.rcv_cnt;     \
		snd = (ring)->stats.snd_cnt;     \
		drp_1 = (ring)->stats.drp_cnt_1; \
		drp_2 = (ring)->stats.drp_cnt_2; \
	} while(0)
#endif

#else

/**
 * Disable statistics specific declarations.
 */
#define NES_STATS_DECL __attribute__((unused))
/**
 * Assign (x) = (y); only if DSTATS is defined.
 * Run (y); otherwise.
 */
#define NES_STATS_ASSGN(x,y) (y)
/**
 * Initialize per device statistics with MAX value if DSTATS is undefined.
 */
#define NES_STATS_INIT_DEV(device){ \
		(device)->stats.rcv_cnt = UINT64_MAX;        \
		(device)->stats.snd_cnt = UINT64_MAX;        \
		(device)->stats.drp_cnt_1 = UINT64_MAX;      \
		(device)->stats.drp_cnt_2 = UINT64_MAX;      \
		(device)->stats.rcv_bytes = UINT64_MAX;      \
		(device)->stats.snd_bytes = UINT64_MAX;      \
		(device)->stats.drp_bytes_1 = UINT64_MAX;    \
		(device)->stats.ip_fragment = UINT64_MAX;    \
	} while(0)
/**
 * Do not update counter only if DSTATS is undefined.
 */
#define NES_STATS_DEV_UPDATE(number, cnt)

#endif


/**
 * Initialize per ring statistics with MAX value only if RSTATS is undefined.
 */
#ifndef NES_STATS_INIT_RING
#define NES_STATS_INIT_RING(ring) do { \
		(ring)->stats.rcv_cnt = UINT64_MAX;        \
		(ring)->stats.snd_cnt = UINT64_MAX;        \
		(ring)->stats.drp_cnt_1 = UINT64_MAX;      \
		(ring)->stats.drp_cnt_2 = UINT64_MAX;      \
	} while(0)
#endif
/**
 * Do not update ring counter only if DSTATS or RSTATS is undefined.
 */
#ifndef NES_STATS_RING_UPDATE
#define NES_STATS_RING_UPDATE(number, cnt)
#endif

#define VHOST_NAME_STRING "VM"
#define KNI_NAME_STRING "KNI"

typedef struct nes_ctrl_dev_s {
	struct nes_dev_s    *dev_ptr;
	nes_dev_stats_t     stats;

	char      name[CTRL_NAME_SIZE];
	uint16_t  index;

	int (*init)(struct nes_ctrl_dev_s *self, void *data);
	int (*update)(struct nes_ctrl_dev_s *self, void *data);
	int (*get)(struct nes_ctrl_dev_s *self, void *data);
	int (*show)(struct nes_ctrl_dev_s *dev, nes_dev_stats_t *stats);

} nes_ctrl_dev_t;

typedef struct nes_ctrl_ring_s {
	struct nes_ring_s   *ring_ptr;
	nes_ring_stats_t    stats;
	char      name[CTRL_NAME_SIZE];
	uint16_t  index;

	int (*init)(struct nes_ctrl_ring_s *self, void *data);
	int (*update)(struct nes_ctrl_ring_s *self, void *data);
	int (*get)(struct nes_ctrl_ring_s *self, void *data);
	int (*show)(struct nes_ctrl_ring_s *ring, nes_ring_stats_t *stats);

} nes_ctrl_ring_t;

extern struct cmdline *nes_cmdline;

/**
 * Structure defining output message from nes to nts
 */
typedef struct nes_message_data_s {
	union {
		struct {
			nts_route_entry_t route_entry;
			nts_route_entry_t vmroute_entry;
		} route;
		struct {
			nts_enc_entry_t encap_entry;
			nes_direction_t direction;
		} encap;
		struct {
			char     *device;
			uint16_t index;
			char     *name;
			uint64_t rcv_pkts;
			uint64_t snd_pkts;
			uint64_t drp_pkts;
		} stats;
	};
	uint32_t ip_addr;
	uint32_t service_ip_addr;
	uint16_t ip_port;
	int      vmid;
} nes_message_data_t;

/**
 * nes control message type from nes to nts
 */
typedef struct nes_message_s {
	uint32_t magic;
	int      retval;
	uint16_t type;
	uint16_t seq;
	nes_message_data_t data;
} nes_message_t;

void nes_ctrl_cmdl_new(void);
int nes_ctrl_init(void);
int nes_ctrl_conn_init(void);
int nes_ctrl_show_dev_stats(uint16_t id, nes_dev_stats_t *stats);
int nes_ctrl_show_ring_stats(uint16_t id, nes_ring_stats_t *stats);
int nes_ctrl_ctor_dev_list(void);
int nes_ctrl_ctor_ring_list(void);
int nes_ctrl_add_device(nes_dev_t *dev, const char *name);
int nes_ctrl_del_device(nes_dev_t *dev);
int nes_ctrl_add_ring(nes_ring_t *ring, const char *name);
int nes_ctrl_del_ring(nes_ring_t *ring);
int nes_ctrl_main(__attribute__((unused))void*);
int nes_ctrl_stats_show_list(void *);
nes_api_msg_t *nes_ctrl_stats_dev(nes_api_msg_t *api_msg);
nes_api_msg_t *nes_ctrl_stats_ring(nes_api_msg_t *api_msg);

#ifdef __cplusplus
}
#endif

#endif /* _NES_CTRL_H_ */
