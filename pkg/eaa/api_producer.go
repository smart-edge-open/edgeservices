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

func addService(commonName string, serv Service, eaaCtx *eaaContext) error {
	if eaaCtx.serviceInfo == nil {
		return errors.New(
			"EAA context is not initialized. Call Init() function first")
	}

	urn, err := CommonNameStringToURN(commonName)
	if err != nil {
		return errors.New(
			"Common name could not be parsed")
	}

	serv.URN = &urn

	if serv.Notifications != nil {

		serv.Notifications = validServiceNotifications(serv.Notifications)

	}
	eaaCtx.serviceInfo[commonName] = serv

	return nil
}

func removeService(commonName string, eaaCtx *eaaContext) (int, error) {
	if eaaCtx.serviceInfo == nil {
		return http.StatusInternalServerError,
			errors.New(
				"EAA context is not initialized. Call Init() function first")
	}

	_, servicefound := eaaCtx.serviceInfo[commonName]
	if servicefound {
		delete(eaaCtx.serviceInfo, commonName)
		return http.StatusNoContent, nil
	}

	return http.StatusNotFound,
		errors.New(http.StatusText(http.StatusNotFound))
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

func sendNotificationToAllSubscribers(commonName string,
	notif NotificationFromProducer, eaaCtx *eaaContext) (int, error) {
	var subscriberList []string

	if eaaCtx.serviceInfo == nil {
		return http.StatusInternalServerError,
			errors.New("EAA context is not initialized")
	}

	prodURN, err := CommonNameStringToURN(commonName)
	if err != nil {
		return http.StatusUnauthorized, err
	}

	msgPayload, err := json.Marshal(NotificationToConsumer{
		Name:    notif.Name,
		Version: notif.Version,
		Payload: notif.Payload,
		URN:     prodURN,
	})
	if err != nil {
		return http.StatusUnauthorized,
			errors.Wrap(err, "Failed to marshal norification JSON")
	}

	_, serviceFound := eaaCtx.serviceInfo[commonName]
	if !serviceFound {
		return http.StatusInternalServerError,
			errors.New("Producer is not registered")
	}

	namespaceKey := UniqueNotif{
		namespace:    prodURN.Namespace,
		notifName:    notif.Name,
		notifVersion: notif.Version,
	}

	namespaceSubsInfo, ok := eaaCtx.subscriptionInfo[namespaceKey]
	if !ok {
		log.Infof("No subscription to notification %v", namespaceKey)
		return http.StatusAccepted, nil
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
	return http.StatusAccepted, nil
}

func sendNotificationToSubscriber(subID string, msgPayload []byte,
	eaaCtx *eaaContext) error {
	possibleConnection, connectionFound := eaaCtx.consumerConnections[subID]
	log.Infof("Looking for websocket: %s from %v", subID,
		eaaCtx.consumerConnections)
	if connectionFound {
		if possibleConnection.connection == nil {
			if err := waitForConnectionAssigned(subID, eaaCtx); err != nil {
				return errors.Wrap(err, "websocket isn't properly created")
			}
		}
		messageType := websocket.TextMessage
		conn := eaaCtx.consumerConnections[subID].connection
		return conn.WriteMessage(messageType, msgPayload)
	}
	return errors.New("no websocket connection created " +
		"by GET /notifications API")
}

// waitForConnectionAssigned waits a second until a proper websocket connection
// is created for subscriber in a separate thread.
// If connection is created then nil in eaaCtx.consumerConnections map
// will be overwritten
func waitForConnectionAssigned(subID string, eaaCtx *eaaContext) error {
	deadline := time.Now().Add(1 * time.Second)
	for {
		if eaaCtx.consumerConnections[subID].connection != nil {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("Timeout reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
