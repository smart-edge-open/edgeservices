// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

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
	eaaCtx := r.Context().Value(contextKey("appliance-ctx")).(*eaaContext)

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
			log.Info("Failed to send close message to old connection")
		}
		err = prevConn.Close()
		if err != nil {
			log.Info("Failed to close previous websocket connection")
		}
		delete(eaaCtx.consumerConnections, commonName)
	}

	// Create nil connection obj in consumerConnections map. That means the
	// procedure of web socket connection has started.
	eaaCtx.consumerConnections[commonName] = ConsumerConnection{
		connection: nil}
	conn, err := socket.Upgrade(w, r, nil)
	if err != nil {
		delete(eaaCtx.consumerConnections, commonName)
		return 0, err
	}

	eaaCtx.consumerConnections[commonName] = ConsumerConnection{
		connection: conn}

	return 0, nil
}

// getConsumerSubscriptions returns a list of subscriptions belonging
// to the consumer
func getConsumerSubscriptions(commonName string,
	eaaCtx *eaaContext) (*SubscriptionList, error) {

	if eaaCtx.subscriptionInfo == nil {
		return nil, errors.New("EAA context not initialized")
	}
	subs := SubscriptionList{}

	for nameNotif, conSub := range eaaCtx.subscriptionInfo {
		// if consumer is in namespace subscription, add it to the list
		if index := getNamespaceSubscriptionIndex(nameNotif,
			commonName, eaaCtx); index != -1 {
			subs.addNamespaceSubscriptionToList(nameNotif, eaaCtx)
		}
		for srvID := range conSub.serviceSubscriptions {
			// if consumer is in service subscription, add it to the list
			if index := getServiceSubscriptionIndex(nameNotif, srvID,
				commonName, eaaCtx); index != -1 {
				subs.addServiceSubscriptionToList(nameNotif, srvID, eaaCtx)
			}
		}

	}
	return &subs, nil
}
