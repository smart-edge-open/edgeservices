// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eaa

import (
	"errors"

	"github.com/gorilla/websocket"
)

// Set read and write buffer sizes for websocket connection, these should be
// based on the message size expected
var socket = websocket.Upgrader{
	ReadBufferSize:  512,
	WriteBufferSize: 512,
}

// getConsumerSubscriptions returns a list of subscriptions belonging
// to the consumer
func getConsumerSubscriptions(commonName string,
	eaaCtx *Context) (*SubscriptionList, error) {

	eaaCtx.subscriptionInfo.RLock()
	defer eaaCtx.subscriptionInfo.RUnlock()

	if eaaCtx.subscriptionInfo.m == nil {
		return nil, errors.New("EAA context not initialized")
	}
	subs := SubscriptionList{}

	for nameNotif, conSub := range eaaCtx.subscriptionInfo.m {
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
