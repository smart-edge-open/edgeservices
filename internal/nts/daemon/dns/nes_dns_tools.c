/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

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
