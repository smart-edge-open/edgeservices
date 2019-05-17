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
	"net/http"

	"github.com/gorilla/websocket"
)

// Set read and write buffer sizes for websocket connection, these should be
// based on the message size expected
var socket = websocket.Upgrader{
	ReadBufferSize:  512,
	WriteBufferSize: 512,
}

func createWsConn(w http.ResponseWriter, r *http.Request) (int, error) {
	// Get the consumer app ID from the Common Name in the certificate
	appID := r.TLS.PeerCertificates[0].Subject.CommonName

	// Check if appID matches the Host included in the request header
	if appID != r.Host {
		return http.StatusUnauthorized,
			errors.New("401: Incorrect app ID")
	}

	// Check that the connection has not already been created for app ID
	_, connFound := eaaCtx.consumerConnections[appID]
	if connFound {
		return http.StatusForbidden,
			errors.New("403: Connection exists for app ID")
	}

	conn, err := socket.Upgrade(w, r, nil)
	if err != nil {
		return 0, err
	}

	eaaCtx.consumerConnections[appID] = ConsumerConnection{connection: conn}

	return 0, nil
}

// getNamespaceSubscriptionIndex returns index of the subscriber id
// in the namespace slice, returns -1 if not found
func getNamespaceSubscriptionIndex(key NamespaceNotif, id string) int {
	for index, subID := range eaaCtx.subscriptionInfo[key].
		namespaceSubscriptions {
		if subID == id {
			return index
		}
	}
	return -1
}

// Checks if consumer is already subscribed to service+namespace+notif set
func checkServiceForConsumer(key NamespaceNotif, serviceID string,
	consID string) int {
	for index, subID := range eaaCtx.subscriptionInfo[key].
		serviceSubscriptions[serviceID] {
		if subID == consID {
			return index
		}
	}

	return -1
}

func addSubscriptionToNamespace(commonName string, namespace string,
	notif []NotificationDescriptor) (int, error) {

	if eaaCtx.subscriptionInfo == nil {
		return http.StatusInternalServerError,
			errors.New("Eaa context not initialized. ")
	}

	for _, n := range notif {

		key := NamespaceNotif{
			namespace: namespace,
			notif:     n}

		addNamespaceNotification(key)

		if index := getNamespaceSubscriptionIndex(key,
			commonName); index == -1 {
			eaaCtx.subscriptionInfo[key].namespaceSubscriptions = append(
				eaaCtx.subscriptionInfo[key].namespaceSubscriptions, commonName)
		}
	}

	return http.StatusOK, nil
}

func removeSubscriptionToNamespace(commonName string, namespace string,
	notif []NotificationDescriptor) (int, error) {

	if eaaCtx.subscriptionInfo == nil {
		return http.StatusInternalServerError,
			errors.New("Eaa context not initialized. ")
	}

	for _, n := range notif {

		key := NamespaceNotif{
			namespace: namespace,
			notif:     n}

		if _, exists := eaaCtx.subscriptionInfo[key]; !exists {
			log.Infof(
				"Couldn't find key \"%s\" in the subscription map. %s",
				key, "(Consumer unsubscription process)")

			continue
		}

		if index := getNamespaceSubscriptionIndex(key,
			commonName); index != -1 {
			eaaCtx.subscriptionInfo[key].namespaceSubscriptions = append(
				eaaCtx.subscriptionInfo[key].namespaceSubscriptions[:index],
				eaaCtx.subscriptionInfo[key].
					namespaceSubscriptions[index+1:]...)
		}
	}

	return http.StatusNoContent, nil
}

func addSubscriptionToService(commonName string, namespace string,
	serviceID string, notif []NotificationDescriptor) (int, error) {

	if eaaCtx.subscriptionInfo == nil {

		return http.StatusInternalServerError,
			errors.New("Eaa context not intialized. ")
	}

	for _, notification := range notif {

		key := NamespaceNotif{
			namespace: namespace,
			notif:     notification}

		// If NamespaceNotif+service set not initialized, do so now
		addServiceNotification(key, serviceID)

		// If Consumer already subscribed, do nothing
		index := checkServiceForConsumer(key, serviceID, commonName)
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

	return http.StatusOK, nil
}

func removeSubscriptionToService(commonName string, namespace string,
	serviceID string, notif []NotificationDescriptor) (int, error) {

	if eaaCtx.subscriptionInfo == nil {
		return http.StatusInternalServerError,
			errors.New("Eaa context not initialized. ")
	}

	for _, n := range notif {

		key := NamespaceNotif{
			namespace: namespace,
			notif:     n}

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

		if index := checkServiceForConsumer(key, serviceID,
			commonName); index != -1 {
			eaaCtx.subscriptionInfo[key].serviceSubscriptions[serviceID] =
				append(eaaCtx.subscriptionInfo[key].
					serviceSubscriptions[serviceID][:index],
					eaaCtx.subscriptionInfo[key].
						serviceSubscriptions[serviceID][index+1:]...)
		}
	}

	return http.StatusNoContent, nil
}

func removeAllSubscriptions(commonName string) (int, error) {
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
					Namespace: nameNotif.namespace},
				Notifications: []NotificationDescriptor{
					nameNotif.notif},
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
					Namespace: nameNotif.namespace},
				Notifications: []NotificationDescriptor{
					nameNotif.notif},
			})
	}
}

func getConsumerSubscriptions(commonName string) (*SubscriptionList, error) {
	if eaaCtx.subscriptionInfo == nil {
		return nil, errors.New("EAA context not initialized")
	}
	subs := SubscriptionList{}

	for nameNotif, conSub := range eaaCtx.subscriptionInfo {
		// if consumer is in namespace subscription, add it to the list
		if index := getNamespaceSubscriptionIndex(nameNotif,
			commonName); index != -1 {
			subs.addNamespaceSubscriptionToList(nameNotif)
		}
		for srvID := range conSub.serviceSubscriptions {
			// if consumer is in service subscription, add it to the list
			if index := checkServiceForConsumer(nameNotif, srvID,
				commonName); index != -1 {
				subs.addServiceSubscriptionToList(nameNotif, srvID)
			}
		}

	}
	return &subs, nil
}
