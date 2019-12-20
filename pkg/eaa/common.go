// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eaa

import (
	"errors"
	"strings"
)

// CommonNameStringToURN parses a common name string to a URN struct
func CommonNameStringToURN(commonName string) (URN, error) {
	splittedCN := strings.SplitN(commonName, ":", 2)

	if len(splittedCN) != 2 {
		return URN{}, errors.New("Cannot translate Common Name to URN")
	}

	return URN{
		Namespace: splittedCN[0],
		ID:        splittedCN[1],
	}, nil
}

// getNamespaceSubscriptionIndex returns index of the subscriber id
// in the namespace slice, returns -1 if not found
func getNamespaceSubscriptionIndex(key UniqueNotif, id string,
	eaaCtx *eaaContext) int {
	for index, subID := range eaaCtx.subscriptionInfo[key].
		namespaceSubscriptions {
		if subID == id {
			return index
		}
	}
	return -1
}

// getServiceSubscriptionIndex returns index of the subscriber id
// in the specified service slice, returns -1 if not found
func getServiceSubscriptionIndex(key UniqueNotif, serviceID string,
	consID string, eaaCtx *eaaContext) int {
	for index, subID := range eaaCtx.subscriptionInfo[key].
		serviceSubscriptions[serviceID] {
		if subID == consID {
			return index
		}
	}

	return -1
}
