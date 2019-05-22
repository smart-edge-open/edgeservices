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

// SubscriberIds stores subscriber ids as a slice of strings
type SubscriberIds []string

// ConsumerSubscription stores namespace notification subscribers
// and a map of services and their subscribers
type ConsumerSubscription struct {
	namespaceSubscriptions SubscriberIds

	// map of producer id to slice of subscriber ids
	serviceSubscriptions map[string]SubscriberIds
}

// NamespaceNotif stores namespace name string and notification data
type NamespaceNotif struct {
	namespace string
	notif     NotificationDescriptor
}

// NotificationSubscriptions is a map of a namespace notification struct
// to the consumer subscription struct
type NotificationSubscriptions map[NamespaceNotif]*ConsumerSubscription

// RemoveSubscriber delete consumer ID from subscribers list
func (sI *SubscriberIds) RemoveSubscriber(commonName string) bool {
	isChanged := false
	for i, subID := range *sI {
		if subID == commonName {
			*sI = append((*sI)[:i], (*sI)[i+1:]...)
			isChanged = true
		}
	}

	return isChanged
}

// initNamespaceNotification initializes structs for given
// NamespaceNotif struct to allow for subscription
func initNamespaceNotification(key NamespaceNotif) {

	if _, ok := eaaCtx.subscriptionInfo[key]; !ok {
		conSub := &ConsumerSubscription{
			namespaceSubscriptions: SubscriberIds{},
			serviceSubscriptions:   map[string]SubscriberIds{}}
		eaaCtx.subscriptionInfo[key] = conSub
	}
}

// initServiceNotification initializes structs for given
// NamespaceNotif struct + serviceID, to allow for subscription
func initServiceNotification(key NamespaceNotif, serviceID string) {

	initNamespaceNotification(key)

	if _, ok := eaaCtx.subscriptionInfo[key].
		serviceSubscriptions[serviceID]; !ok {
		eaaCtx.subscriptionInfo[key].serviceSubscriptions[serviceID] =
			SubscriberIds{}
	}
}

// addNamespaceSubscriptionToList adds a namespace subscription
// to a list of subscriptions
func (sL *SubscriptionList) addNamespaceSubscriptionToList(
	nameNotif NamespaceNotif) {
	found := false

	for _, s := range sL.Subscriptions {
		if s.URN.ID == "" && s.URN.Namespace == nameNotif.namespace {
			s.Notifications = append(s.Notifications, nameNotif.notif)
			found = true
			break
		}
	}
	if !found {
		sL.Subscriptions = append(sL.Subscriptions,
			Subscription{
				URN: &URN{
					ID:        "",
					Namespace: nameNotif.namespace,
				},
				Notifications: []NotificationDescriptor{
					nameNotif.notif,
				},
			})
	}
}

// addServiceSubscriptionToList adds a service subscription
// to a list of subscriptions
func (sL *SubscriptionList) addServiceSubscriptionToList(
	nameNotif NamespaceNotif, srvID string) {
	found := false

	for _, s := range sL.Subscriptions {
		if s.URN.Namespace == nameNotif.namespace &&
			s.URN.ID == srvID {
			s.Notifications = append(s.Notifications,
				nameNotif.notif)
			found = true
			break
		}
	}
	if !found {
		sL.Subscriptions = append(sL.Subscriptions,
			Subscription{
				URN: &URN{
					ID:        srvID,
					Namespace: nameNotif.namespace,
				},
				Notifications: []NotificationDescriptor{
					nameNotif.notif,
				},
			})
	}
}
