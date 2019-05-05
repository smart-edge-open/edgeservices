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

// notifID is Name + Version from NotificationDescriptor struct

// Initializes structs for given namespace + notifID, to allow for subscription
func addNamespaceNotification(namespace string, notifID string) {

	key := namespace + notifID

	if conSub, ok := eaaCtx.subscriptionInfo[key]; !ok {
		conSub.namespaceSubscriptions = SubscriberIds{}
		if conSub.serviceSubscriptions == nil {
			conSub.serviceSubscriptions = map[string]SubscriberIds{}
		}
		eaaCtx.subscriptionInfo[key] = conSub
	}
}

// Initializes structs for given namespace + notifID + serviceID,
//	to allow for subscription
func addServiceNotification(namespace string, notifID string,
	serviceID string) {

	addNamespaceNotification(namespace, notifID)

	key := namespace + notifID

	_, ok := eaaCtx.subscriptionInfo[key].serviceSubscriptions[serviceID]

	if !ok {
		eaaCtx.subscriptionInfo[key].serviceSubscriptions[serviceID] =
			SubscriberIds{}
	}
}
