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
 * @file libnes_api_protocol.h
 * @brief Header file for devices packets counting
 */
#ifndef _LIBNES_API_PROTOCOL_H_
#define _LIBNES_API_PROTOCOL_H_
#ifdef __cplusplus
extern "C" {
#endif

typedef enum nes_api_msg_type
{
	eRequest,
	eResponse,
	eError,
} nes_api_msg_type_t;

typedef enum nes_api_funtion_id
{
	eNesStatsDevAll,
	eNesStatsDev,
	eNesStatsShowList,
	eNesMacAddressGet,
	eNesAddRoute,
	eNesAddMirror,
	eNesShowRoute,
	eNesDelRoute,
	eNesRouteClearAll,
	eNesStatsClearAll,
	eNesStatsRingAll,
	eNesStatsRing,
	eNesAddKni,
	eNesDelKni,
	eNesRouteList
	// here define values for all possible api/control commands
} nes_api_function_id_t;

typedef struct nes_api_msg
{
	uint16_t message_type;
	uint16_t function_id;
	uint16_t data_size;
	uint8_t  data[];
} __attribute__((__packed__)) nes_api_msg_t;

#ifdef __cplusplus
}
#endif
#endif /* _LIBNES_API_PROTOCOL_H_ */
