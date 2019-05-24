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
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"
)

func addService(commonName string, serv Service) error {
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

	eaaCtx.serviceInfo[commonName] = serv

	return nil
}

func removeService(commonName string) (int, error) {
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

func findServiceNotifIndex(servInfo Service, notif Notification) int {
	for idx, servNotif := range servInfo.Notifications {
		nameComp := strings.Compare(notif.Name, servNotif.Name)
		verComp := strings.Compare(notif.Version, servNotif.Version)

		if nameComp == 0 && verComp == 0 {
			return idx
		}
	}

	return -1
}

func sendNotificationToSubscribers(commonName string,
	notif Notification) (int, error) {
	var subscriberList []string
	retCode := http.StatusAccepted

	if eaaCtx.serviceInfo == nil {
		return http.StatusInternalServerError,
			errors.New("EAA context is not initialized")
	}

	prodURN, err := CommonNameStringToURN(commonName)
	if err != nil {
		return http.StatusUnauthorized, err
	}

	msgPayload, err := json.Marshal(notif.Payload)
	if err != nil {
		return http.StatusUnauthorized, err
	}

	serviceInfo, serviceFound := eaaCtx.serviceInfo[commonName]
	if !serviceFound {
		return http.StatusInternalServerError,
			errors.New("Unable to find service information")
	}

	servNotifIdx := findServiceNotifIndex(serviceInfo, notif)
	if servNotifIdx == -1 {
		return http.StatusInternalServerError,
			errors.New("Unable to find notification information")
	}
	servNotif := serviceInfo.Notifications[servNotifIdx]

	namespaceKey := UniqueNotif{
		namespace:    prodURN.Namespace,
		notifName:    servNotif.Name,
		notifVersion: servNotif.Version,
	}

	namespaceSubsInfo, ok := eaaCtx.subscriptionInfo[namespaceKey]
	if !ok {
		log.Infof("No subscription to notification %v", namespaceKey)
		return retCode, nil
	}

	srvSubsList, ok := namespaceSubsInfo.serviceSubscriptions[prodURN.ID]

	if !ok {
		subscriberList = namespaceSubsInfo.namespaceSubscriptions
	} else {
		subscriberList = getUniqueSubsList(
			namespaceSubsInfo.namespaceSubscriptions, srvSubsList)
	}

	for _, subID := range subscriberList {
		_, connectionFound := eaaCtx.consumerConnections[subID]
		if connectionFound {
			messageType := websocket.TextMessage
			conn := eaaCtx.consumerConnections[subID].connection
			err = conn.WriteMessage(messageType, msgPayload)
			if err != nil {
				retCode = http.StatusForbidden
			}
		} else {
			retCode = http.StatusForbidden
			err = errors.New("No connection found")
		}
	}

	return retCode, err
}
