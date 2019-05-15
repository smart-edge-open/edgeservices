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

// Initializes structs for given NamespaceNotif struct
// to allow for subscription
func addNamespaceNotification(key NamespaceNotif) {

	if _, ok := eaaCtx.subscriptionInfo[key]; !ok {
		conSub := &ConsumerSubscription{
			namespaceSubscriptions: SubscriberIds{},
			serviceSubscriptions:   map[string]SubscriberIds{}}
		eaaCtx.subscriptionInfo[key] = conSub
	}
}

// Initializes structs for given NamespaceNotif struct + serviceID,
//	to allow for subscription
func addServiceNotification(key NamespaceNotif, serviceID string) {

	addNamespaceNotification(key)

	if _, ok := eaaCtx.subscriptionInfo[key].
		serviceSubscriptions[serviceID]; !ok {
		eaaCtx.subscriptionInfo[key].serviceSubscriptions[serviceID] =
			SubscriberIds{}
	}
}
