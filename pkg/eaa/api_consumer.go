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

// createWsConn creates a websocket connection for a consumer
// to receive data from subscribed producers
func createWsConn(w http.ResponseWriter, r *http.Request) (int, error) {
	// Get the consumer app ID from the Common Name in the certificate
	commonName := r.TLS.PeerCertificates[0].Subject.CommonName

	// Check if urn ID matches the Host included in the request header
	if commonName != r.Host {
		return http.StatusUnauthorized,
			errors.New("401: Incorrect app ID")
	}

	// Check if connection was created for urn ID, if so send close
	// message, close the connection and delete the entry in the
	// connections structure
	foundConn, connFound := eaaCtx.consumerConnections[commonName]
	if connFound {
		prevConn := foundConn.connection
		msgType := websocket.CloseMessage
		closeMessage := websocket.FormatCloseMessage(
			websocket.CloseServiceRestart,
			"New connection request, closing this connection")
		err := prevConn.WriteMessage(msgType, closeMessage)
		if err != nil {
			return http.StatusInternalServerError,
				errors.New("Failed to send close message to old connection")
		}
		err = prevConn.Close()
		if err != nil {
			return http.StatusInternalServerError,
				errors.New("Failed to close previous websocket connection")
		}
		delete(eaaCtx.consumerConnections, commonName)
	}

	conn, err := socket.Upgrade(w, r, nil)
	if err != nil {
		return 0, err
	}

	eaaCtx.consumerConnections[commonName] = ConsumerConnection{
		connection: conn}

	return 0, nil
}

// getConsumerSubscriptions returns a list of subscriptions belonging
// to the consumer
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
			if index := getServiceSubscriptionIndex(nameNotif, srvID,
				commonName); index != -1 {
				subs.addServiceSubscriptionToList(nameNotif, srvID)
			}
		}

	}
	return &subs, nil
}
