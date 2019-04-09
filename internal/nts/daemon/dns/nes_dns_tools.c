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
 * @file nes_dns_tools.c
 * @brief implementation of nes_dns_tools
 */

#include <assert.h>
#include <stdio.h>
#include <stdint.h>

#include "nes_dns_tools.h"

int
nes_dns_labels_to_domain(const char *labels, char *domain, uint8_t domain_len) {
	assert(labels);
	assert(domain);

	uint8_t label_len, labels_len,
		offset = 1; // offset is 1 because first byte defines first label length

	labels_len = strlen(labels);
	if (labels_len > domain_len)
		return NES_FAIL;

	memset(domain, 0, domain_len);
	label_len = labels[0];

	while (1) {
		if (offset > labels_len || label_len > (domain_len - strlen(domain)))
			return NES_FAIL;

		strncat(domain, labels + offset, label_len);
		offset += label_len + 1; //move past next label length byte
		label_len = labels[offset - 1];
		if (label_len > 0 && 0 == (label_len & 0xC0))
			strcat(domain, ".");
		else
			break;
	}
	return NES_SUCCESS;

}
