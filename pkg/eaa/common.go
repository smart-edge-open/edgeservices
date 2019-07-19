// Copyright 2019 Intel Corporation and Smart-Edge.com, Inc. All rights reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
