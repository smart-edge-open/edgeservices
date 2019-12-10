// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eaa

// SubscriberIds stores subscriber ids as a slice of strings
type SubscriberIds []string

// ConsumerSubscription stores namespace notification subscribers
// and a map of services and their subscribers
type ConsumerSubscription struct {
	namespaceSubscriptions SubscriberIds

	// map of producer id to slice of subscriber ids
	serviceSubscriptions map[string]SubscriberIds
	notification         NotificationDescriptor
}

// UniqueNotif stores information about unique notification. It is used as
// a key in NotificationSubscriptions map
type UniqueNotif struct {
	namespace    string
	notifName    string
	notifVersion string
}

// NotificationSubscriptions is a map of a namespace notification struct
// to the consumer subscription struct
type NotificationSubscriptions map[UniqueNotif]*ConsumerSubscription

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
func initNamespaceNotification(key UniqueNotif, notif NotificationDescriptor,
	eaaCtx *eaaContext) {
	if _, ok := eaaCtx.subscriptionInfo[key]; !ok {
		conSub := &ConsumerSubscription{
			namespaceSubscriptions: SubscriberIds{},
			serviceSubscriptions:   map[string]SubscriberIds{},
			notification:           notif,
		}
		eaaCtx.subscriptionInfo[key] = conSub
	}
}

// initServiceNotification initializes structs for given
// NamespaceNotif struct + serviceID, to allow for subscription
func initServiceNotification(key UniqueNotif, serviceID string,
	notif NotificationDescriptor, eaaCtx *eaaContext) {
	initNamespaceNotification(key, notif, eaaCtx)

	if _, ok := eaaCtx.subscriptionInfo[key].
		serviceSubscriptions[serviceID]; !ok {
		eaaCtx.subscriptionInfo[key].serviceSubscriptions[serviceID] =
			SubscriberIds{}
	}
}

// addNamespaceSubscriptionToList adds a namespace subscription
// to a list of subscriptions
func (sL *SubscriptionList) addNamespaceSubscriptionToList(
	nameNotif UniqueNotif, eaaCtx *eaaContext) {
	found := false

	for i, s := range sL.Subscriptions {
		if s.URN.ID == "" && s.URN.Namespace == nameNotif.namespace {
			sL.Subscriptions[i].Notifications = append(
				sL.Subscriptions[i].Notifications,
				eaaCtx.subscriptionInfo[nameNotif].notification)
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
					eaaCtx.subscriptionInfo[nameNotif].notification,
				},
			})
	}
}

// addServiceSubscriptionToList adds a service subscription
// to a list of subscriptions
func (sL *SubscriptionList) addServiceSubscriptionToList(
	nameNotif UniqueNotif, srvID string, eaaCtx *eaaContext) {
	found := false

	for i, s := range sL.Subscriptions {
		if s.URN.Namespace == nameNotif.namespace &&
			s.URN.ID == srvID {
			sL.Subscriptions[i].Notifications = append(
				sL.Subscriptions[i].Notifications,
				eaaCtx.subscriptionInfo[nameNotif].notification)
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
					eaaCtx.subscriptionInfo[nameNotif].notification,
				},
			})
	}
}
