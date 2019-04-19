/*******************************************************************************
* Copyright 2019 Intel Corporation. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/


/**
* @file nes_main.c
* @brief Main for nes
*/
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <rte_config.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_eal.h>
#include <rte_log.h>
#include <rte_ethdev.h>
#include <rte_vhost.h>

#include "nes_main.h"
#include "io/nes_dev.h"
#include "io/nes_dev_kni.h"
#include "nes_ring.h"
#include "io/nes_io.h"
#include "nis/nis_io.h"
#include "nts/nts_io.h"
#include "ctrl/nes_ctrl.h"
#include "dns/nes_dns.h"
#include "nes_latency.h"
#include "libnes_cfgfile.h"
#include "libnes_daemon.h"
#include "io/nes_dev_addons.h"

#define MBUF_CACHE_SIZE 512
#define MBUF_OVERHEAD (sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define MBUF_DATA_SIZE 2048
#define MBUF_SIZE (MBUF_DATA_SIZE + MBUF_OVERHEAD)

#define PKTMBUF_POOL_NAME "MProc_pktmbuf_pool"
#define PKTMBUF_INDIR_POOL_NAME "MProc_pktmbuf_indir_pool"
#define NES_SERVER_CONF_DEFAULT_PATH "/opt/intel/nev_sdk/nes_root/scripts/nes.cfg"
#define NES_LOG_FILE "/var/log/nes.log"

struct rte_mempool *nes_main_pktmbuf_pool;
struct rte_mempool *nes_main_indir_pktmbuf_pool;

NES_STATIC int nes_init_interfaces(void)
{
	nes_dev_tabq_init();

	if (NES_FAIL == nes_ctrl_ctor_dev_list()) {
		NES_LOG(ERR,"Can't create devices list.\n");
		return NES_FAIL;
	}

	nes_dev_eth_start_stats_timer();
	nes_dev_port_dtor();

	if (NES_SUCCESS != nes_dev_port_new_device()) {
		NES_LOG(EMERG, "nes_dev_port_new_device initialization failed!");
		nes_dev_port_dtor();
		return NES_FAIL;
	}
	return NES_SUCCESS;
}

NES_STATIC void nes_handle_signals(int signal) {
	if (signal == SIGTERM || signal == SIGINT) {
		NES_LOG(INFO, "Signal received, exiting now...\n");

		const char *dev_basename;
		if (NES_SUCCESS != nes_cfgfile_entry("VM common", "vhost-dev", &dev_basename)) {
			NES_LOG(ERR,
				"Missing: section VM common, entry vhost-dev, in config file.\n");
		} else
			rte_vhost_driver_unregister(dev_basename);

		if (NES_SUCCESS == nes_cfgfile_has_section("KNI"))
			nes_dev_kni_stop();

		NES_EXIT(0);
	}
}

NES_STATIC int nes_mempool_init(void)
{
	const unsigned num_mbufs = (nes_ring_norings() * MBUFS_PER_RING) +
		((count_port_devices() + 1) * MBUFS_PER_PORT);

	nes_main_pktmbuf_pool = rte_mempool_create(
		PKTMBUF_POOL_NAME,
		num_mbufs,
		MBUF_SIZE,
		MBUF_CACHE_SIZE,
		sizeof(struct rte_pktmbuf_pool_private),
		rte_pktmbuf_pool_init,
		NULL,
		rte_pktmbuf_init,
		NULL,
		rte_socket_id(),
		0);
	if (NULL == nes_main_pktmbuf_pool) {
		NES_LOG(ERR, "Initialization of mbufs failed.\n");
		return NES_FAIL;
	}

	nes_main_indir_pktmbuf_pool = rte_mempool_create(
		PKTMBUF_INDIR_POOL_NAME,
		num_mbufs,
		MBUF_SIZE,
		MBUF_CACHE_SIZE,
		sizeof(struct rte_pktmbuf_pool_private),
		rte_pktmbuf_pool_init,
		NULL,
		rte_pktmbuf_init,
		NULL,
		rte_socket_id(),
		0);
	if (NULL == nes_main_indir_pktmbuf_pool) {
		NES_LOG(ERR, "Initialization of indirect mbufs failed.\n");
		return NES_FAIL;
	}

	return NES_SUCCESS;
}

int NES_MAIN(int argc, char** argv)
{
	char   *nes_conf_path = NULL;
	struct sigaction sa;
	sa.sa_handler = &nes_handle_signals;
	sa.sa_flags = SA_RESTART;
	sigfillset(&sa.sa_mask);

	if (sigaction(SIGTERM, &sa, NULL) == -1 || sigaction(SIGINT, &sa, NULL) == -1) {
		NES_LOG(ERR, "Cannot handle signals");
		return NES_FAIL;
	}

	int eal_args, io_lcore = 1, nts_lcore = 2, nis_lcore = 3, nts_ctrl_lcore = 4,
		nts_dns_agent_lcore = 5;
	eal_args = rte_eal_init(argc, argv);
	argc -= eal_args;
	argv += eal_args;

	/* check if environment variable NES_SERVER_CONF exists */
	nes_conf_path = getenv("NES_SERVER_CONF");
	if (NULL == nes_conf_path)
		nes_conf_path = (char*)(uintptr_t)NES_SERVER_CONF_DEFAULT_PATH;

	/* try to load config file from default localization or defined in environment variable */
	if (NES_FAIL == nes_cfgfile_load(nes_conf_path)) {
		NES_LOG(INFO, "Could not load config file %s.\n", nes_conf_path);

		if (NES_FAIL == nes_cfgfile_load(argv[1])) {
			NES_LOG(ERR, "Could not load config file %s.\n", argv[1]);
			return NES_FAIL;
		}
	}
	if (NES_FAIL == nes_mempool_init()) {
		NES_LOG(ERR, "Could not initialize memory pool.\n");
		return NES_FAIL;
	}

	nes_ring_init();

	if (NES_FAIL == nes_init_interfaces()) {
		NES_LOG(ERR, "Could not initialize interfaces.\n");
		return NES_FAIL;
	}
	rte_eal_remote_launch(nes_io_main, NULL, io_lcore);
	rte_eal_remote_launch(nts_io_main, NULL, nts_lcore);
	rte_eal_remote_launch(nis_io_main, NULL, nis_lcore);
	rte_eal_remote_launch(nes_ctrl_main, NULL, nts_ctrl_lcore);
	rte_eal_remote_launch(nes_dns_agent_main, NULL, nts_dns_agent_lcore);
	NES_LATENCY_START_THREAD(nts_dns_agent_lcore + 1);
	if (NES_SUCCESS != is_avp_enabled()) {
		if (NES_SUCCESS == nes_cfgfile_has_section("KNI")) {
			if (NES_SUCCESS != nes_dev_kni_init()) {
				NES_LOG(ERR,
					"Failed to initialize KNI, is rte_kni module loaded?\n");
				return NES_FAIL;
			}
			NES_LOG(INFO, "KNI initialized\n");
		}
		if (NES_SUCCESS != nes_dev_vhost_early_init()) {
			return NES_FAIL;
		}
	}
	if (rte_eal_wait_lcore(io_lcore) < 0) {
		return NES_FAIL;
	}

	nes_cfgfile_close();
	return NES_SUCCESS;
}
