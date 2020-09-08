// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eaa

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
)

func validServiceNotifications(
	servNotifications []NotificationDescriptor) []NotificationDescriptor {

	var validNotificationList []NotificationDescriptor

	for _, notif := range servNotifications {

		if notif.Name == "" || notif.Version == "" {

			log.Errf("Service notification is invalid - missing required" +
				" fields: Name or Version")
		} else {
			validNotificationList = append(validNotificationList, notif)
		}
	}
	return validNotificationList
}

func isServicePresent(commonName string, eaaCtx *Context) bool {
	_, serviceFound := eaaCtx.serviceInfo.m[commonName]
	return serviceFound
}

func addService(commonName string, serv Service, eaaCtx *Context) error {
	eaaCtx.serviceInfo.Lock()
	defer eaaCtx.serviceInfo.Unlock()

	if eaaCtx.serviceInfo.m == nil {
		return errors.New(
			"EAA context is not initialized. Call Init() function first")
	}

	if serv.Notifications != nil {
		serv.Notifications = validServiceNotifications(serv.Notifications)
	}

	eaaCtx.serviceInfo.m[commonName] = serv
	log.Infof("Successfully added '%v' service", commonName)

	return nil
}

func removeService(commonName string, eaaCtx *Context) error {
	eaaCtx.serviceInfo.Lock()
	defer eaaCtx.serviceInfo.Unlock()

	if eaaCtx.serviceInfo.m == nil {
		return errors.New("EAA context is not initialized. Call Init() function first")
	}

	servicefound := isServicePresent(commonName, eaaCtx)
	if servicefound {
		delete(eaaCtx.serviceInfo.m, commonName)
		log.Infof("Successfully removed '%v' service", commonName)
		return nil
	}

	return errors.New(http.StatusText(http.StatusNotFound))
}

func getUniqueSubsList(nsList []string, servList []string) []string {
	fullList := nsList

	for _, subID := range servList {
		isNamespaceSubscribed := false
		for _, nsSubID := range nsList {
			if res := strings.Compare(subID, nsSubID); res == 0 {
				isNamespaceSubscribed = true
				break
			}
		}
		if !isNamespaceSubscribed {
			fullList = append(fullList, subID)
		}
	}

	return fullList
}

func sendNotificationToAllSubscribers(commonName string, notif *NotificationFromProducer,
	eaaCtx *Context) error {

	var subscriberList []string

	eaaCtx.serviceInfo.RLock()
	defer eaaCtx.serviceInfo.RUnlock()

	if eaaCtx.serviceInfo.m == nil {
		return errors.New("EAA context is not initialized")
	}

	prodURN, err := CommonNameStringToURN(commonName)
	if err != nil {
		return err
	}

	msgPayload, err := json.Marshal(NotificationToConsumer{
		Name:    notif.Name,
		Version: notif.Version,
		Payload: notif.Payload,
		URN:     prodURN,
	})
	if err != nil {
		return errors.Wrap(err, "Failed to marshal norification JSON")
	}

	_, serviceFound := eaaCtx.serviceInfo.m[commonName]
	if !serviceFound {
		return errors.New("Producer is not registered")
	}

	namespaceKey := UniqueNotif{
		namespace:    prodURN.Namespace,
		notifName:    notif.Name,
		notifVersion: notif.Version,
	}

	eaaCtx.subscriptionInfo.RLock()
	defer eaaCtx.subscriptionInfo.RUnlock()

	namespaceSubsInfo, ok := eaaCtx.subscriptionInfo.m[namespaceKey]
	if !ok {
		log.Infof("No subscription to notification %v", namespaceKey)
		return nil
	}

	srvSubsList, ok := namespaceSubsInfo.serviceSubscriptions[prodURN.ID]

	if !ok {
		subscriberList = namespaceSubsInfo.namespaceSubscriptions
	} else {
		subscriberList = getUniqueSubsList(
			namespaceSubsInfo.namespaceSubscriptions, srvSubsList)
	}

	for _, subID := range subscriberList {
		if err = sendNotificationToSubscriber(subID, msgPayload,
			eaaCtx); err != nil {
			log.Warningf("Couldn't send notification to Subscriber ID: %s : %v",
				subID, err)
		}
	}
	return nil
}

func sendNotificationToSubscriber(subID string, msgPayload []byte,
	eaaCtx *Context) error {

	eaaCtx.consumerConnections.RLock()

	possibleConnection, connectionFound := eaaCtx.consumerConnections.m[subID]
	log.Infof("Looking for websocket: %s from %v", subID,
		eaaCtx.consumerConnections.m)
	if connectionFound {
		if possibleConnection.connection == nil {
			// Unlock consumer connections to allow the other thread to update it
			eaaCtx.consumerConnections.RUnlock()

			if err := waitForConnectionAssigned(subID, eaaCtx); err != nil {
				return errors.Wrap(err, "websocket isn't properly created")
			}
			eaaCtx.consumerConnections.RLock()
		}
		messageType := websocket.TextMessage
		conn := eaaCtx.consumerConnections.m[subID].connection
		err := conn.WriteMessage(messageType, msgPayload)
		eaaCtx.consumerConnections.RUnlock()
		return err
	}

	eaaCtx.consumerConnections.RUnlock()
	return errors.New("no websocket connection created " +
		"by GET /notifications API")
}

// waitForConnectionAssigned waits a second until a proper websocket connection
// is created for subscriber in a separate thread.
// If connection is created then nil in eaaCtx.consumerConnections map
// will be overwritten
func waitForConnectionAssigned(subID string, eaaCtx *Context) error {
	deadline := time.Now().Add(1 * time.Second)
	for {
		eaaCtx.consumerConnections.RLock()
		if eaaCtx.consumerConnections.m[subID].connection != nil {
			eaaCtx.consumerConnections.RUnlock()
			return nil
		}
		// Unlock consumer connections to allow the other thread to update it
		eaaCtx.consumerConnections.RUnlock()

		if time.Now().After(deadline) {
			return errors.New("Timeout reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
