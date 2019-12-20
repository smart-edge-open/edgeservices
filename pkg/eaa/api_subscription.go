// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eaa

import (
	"errors"
	"net/http"
)

// addSubscriptionToNamespace subscribes a consumer to a notification
// in a namespace
func addSubscriptionToNamespace(commonName string, namespace string,
	notif []NotificationDescriptor, eaaCtx *eaaContext) (int, error) {
	if eaaCtx.subscriptionInfo == nil {
		return http.StatusInternalServerError,
			errors.New("Eaa context not initialized. ")
	}

	for _, n := range notif {
		key := UniqueNotif{
			namespace:    namespace,
			notifName:    n.Name,
			notifVersion: n.Version,
		}

		initNamespaceNotification(key, n, eaaCtx)

		if index := getNamespaceSubscriptionIndex(key,
			commonName, eaaCtx); index == -1 {
			eaaCtx.subscriptionInfo[key].namespaceSubscriptions = append(
				eaaCtx.subscriptionInfo[key].namespaceSubscriptions, commonName)
		}
	}

	return http.StatusCreated, nil
}

// removeSubscriptionToNamespace unsubscribes a consumer from a specified
// notification in a namespace
func removeSubscriptionToNamespace(commonName string, namespace string,
	notif []NotificationDescriptor, eaaCtx *eaaContext) (int, error) {
	if eaaCtx.subscriptionInfo == nil {
		return http.StatusInternalServerError,
			errors.New("Eaa context not initialized. ")
	}

	for _, n := range notif {
		key := UniqueNotif{
			namespace:    namespace,
			notifName:    n.Name,
			notifVersion: n.Version,
		}

		if _, exists := eaaCtx.subscriptionInfo[key]; !exists {
			log.Infof(
				"Couldn't find key \"%s\" in the subscription map. %s",
				key, "(Consumer unsubscription process)")

			continue
		}
		if index := getNamespaceSubscriptionIndex(key,
			commonName, eaaCtx); index != -1 {
			eaaCtx.subscriptionInfo[key].namespaceSubscriptions = append(
				eaaCtx.subscriptionInfo[key].namespaceSubscriptions[:index],
				eaaCtx.subscriptionInfo[key].
					namespaceSubscriptions[index+1:]...)
		}
	}

	return http.StatusNoContent, nil
}

// addSubscriptionToService subscribes a consumer to a notification
// in a specified service within a namespace
func addSubscriptionToService(commonName string, namespace string,
	serviceID string, notif []NotificationDescriptor,
	eaaCtx *eaaContext) (int, error) {
	if eaaCtx.subscriptionInfo == nil {
		return http.StatusInternalServerError,
			errors.New("Eaa context not intialized. ")
	}

	for _, n := range notif {
		key := UniqueNotif{
			namespace:    namespace,
			notifName:    n.Name,
			notifVersion: n.Version,
		}

		// If NamespaceNotif+service set not initialized, do so now
		initServiceNotification(key, serviceID, n, eaaCtx)

		// If Consumer already subscribed, do nothing
		index := getServiceSubscriptionIndex(key, serviceID, commonName, eaaCtx)
		if index != -1 {
			log.Infof("%s is already subscribed to %s - %s",
				commonName, key, serviceID)
			continue
		}

		// Add Consumer to Subscriber list
		eaaCtx.subscriptionInfo[key].serviceSubscriptions[serviceID] =
			append(eaaCtx.subscriptionInfo[key].serviceSubscriptions[serviceID],
				commonName)
	}

	return http.StatusCreated, nil
}

// removeSubscriptionToService unsubscribes a consumer from
// a notification in specified service within a namespace
func removeSubscriptionToService(commonName string,
	namespace string,
	serviceID string,
	notif []NotificationDescriptor,
	eaaCtx *eaaContext) (int, error) {
	if eaaCtx.subscriptionInfo == nil {
		return http.StatusInternalServerError,
			errors.New("Eaa context not initialized. ")
	}

	for _, n := range notif {
		key := UniqueNotif{
			namespace:    namespace,
			notifName:    n.Name,
			notifVersion: n.Version,
		}

		if _, exists := eaaCtx.subscriptionInfo[key]; !exists {
			log.Infof(
				"Couldn't find key \"%s\" in the subscription map. %s",
				key, "(Consumer unsubscription process)")
			continue
		}

		if _, exists := eaaCtx.subscriptionInfo[key].
			serviceSubscriptions[serviceID]; !exists {
			log.Infof(
				"Couldn't find key \"%s\" in the service subscription map. %s",
				serviceID,
				"(Consumer unsubscription process)")
			continue
		}

		if index := getServiceSubscriptionIndex(key, serviceID,
			commonName, eaaCtx); index != -1 {
			eaaCtx.subscriptionInfo[key].serviceSubscriptions[serviceID] =
				append(eaaCtx.subscriptionInfo[key].
					serviceSubscriptions[serviceID][:index],
					eaaCtx.subscriptionInfo[key].
						serviceSubscriptions[serviceID][index+1:]...)
		}
	}

	return http.StatusNoContent, nil
}

// removeAllSubscriptions unsubscribes a consumer from
// all notifications in all namespaces and services
func removeAllSubscriptions(commonName string,
	eaaCtx *eaaContext) (int, error) {
	if eaaCtx.subscriptionInfo == nil {
		return http.StatusInternalServerError,
			errors.New("EAA context not initialized")
	}

	for _, nsSubsInfo := range eaaCtx.subscriptionInfo {
		for srvID, srvSubsInfo := range nsSubsInfo.serviceSubscriptions {
			if srvSubsInfo.RemoveSubscriber(commonName) {
				nsSubsInfo.serviceSubscriptions[srvID] = srvSubsInfo
			}
		}

		nsSubsInfo.namespaceSubscriptions.RemoveSubscriber(commonName)
	}

	return http.StatusNoContent, nil
}
