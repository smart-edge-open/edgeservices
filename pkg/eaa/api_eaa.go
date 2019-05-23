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
	"net/http"

	"github.com/gorilla/mux"
)

func DeregisterApplication(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	clientCert := r.TLS.PeerCertificates[0]
	commonName := clientCert.Subject.CommonName
	statCode, err := removeService(commonName)

	w.WriteHeader(statCode)

	if err != nil {
		log.Errf("Error in Service Deregistration: %s", err.Error())
	}
}

func GetNotifications(w http.ResponseWriter, r *http.Request) {
	if eaaCtx.serviceInfo == nil {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusInternalServerError)
	}

	statCode, err := createWsConn(w, r)
	if err != nil {
		log.Errf("Error in WebSocket Connection Creation: %#v", err)
		if statCode != 0 {
			w.Header().Set("Content-Type", "application/json; charset=UTF-8")
			w.WriteHeader(statCode)
		}
		return
	}
}

func GetServices(w http.ResponseWriter, r *http.Request) {
	var servList ServiceList
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	if eaaCtx.serviceInfo == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	for _, serv := range eaaCtx.serviceInfo {
		servList.Services = append(servList.Services, serv)
	}

	encoder := json.NewEncoder(w)
	err := encoder.Encode(servList)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func GetSubscriptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	var (
		subs       *SubscriptionList
		commonName string
		err        error
	)

	commonName = r.TLS.PeerCertificates[0].Subject.CommonName

	if subs, err = getConsumerSubscriptions(commonName); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Errf("Consumer Subscription List Getter: %s",
			err.Error())
		return
	}

	if err = json.NewEncoder(w).Encode(*subs); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Errf("Consumer Subscription List Getter: %s",
			err.Error())
		return
	}

	w.WriteHeader(http.StatusOK)
}

func PushNotificationToSubscribers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	var notif Notification

	commonName := r.TLS.PeerCertificates[0].Subject.CommonName

	err := json.NewDecoder(r.Body).Decode(&notif)
	if err != nil {
		log.Errf("Error in Publish Notification: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	statCode, err := sendNotificationToSubscribers(commonName, notif)
	if err != nil {
		log.Errf("Error in Publish Notification: %s", err.Error())
	}

	w.WriteHeader(statCode)
}

func RegisterApplication(w http.ResponseWriter, r *http.Request) {
	var serv Service
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	clientCert := r.TLS.PeerCertificates[0]
	commonName := clientCert.Subject.CommonName

	err := json.NewDecoder(r.Body).Decode(&serv)
	if err != nil {
		log.Errf("Register Application: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err = addService(commonName, serv); err != nil {
		log.Errf("Register Application: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func SubscribeNamespaceNotifications(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	var (
		sub        Subscription
		commonName string
		err        error
		statCode   int
	)

	if err = json.NewDecoder(r.Body).Decode(&sub); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Errf("Namespace Notification Registration: %s",
			err.Error())
		return
	}

	commonName = r.TLS.PeerCertificates[0].Subject.CommonName

	vars := mux.Vars(r)

	statCode, err = addSubscriptionToNamespace(commonName,
		vars["urn.namespace"], sub.Notifications)

	if err != nil {
		log.Errf("Namespace Notification Registration: %s",
			err.Error())
	}

	w.WriteHeader(statCode)
}

func SubscribeServiceNotifications(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	var (
		sub        Subscription
		commonName string
		err        error
		statCode   int
	)

	if err = json.NewDecoder(r.Body).Decode(&sub); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Errf("Service Notification Registration: %s", err.Error())
		return
	}

	commonName = r.TLS.PeerCertificates[0].Subject.CommonName

	vars := mux.Vars(r)

	statCode, err = addSubscriptionToService(commonName,
		vars["urn.namespace"], vars["urn.id"], sub.Notifications)

	if err != nil {
		log.Errf("Service Notification Registration: %s", err.Error())
	}

	w.WriteHeader(statCode)
}

func UnsubscribeAllNotifications(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	commonName := r.TLS.PeerCertificates[0].Subject.CommonName
	statCode, err := removeAllSubscriptions(commonName)
	if err != nil {
		log.Errf("Error in UnsubscribeAllNotifications: %s", err.Error())
	}

	w.WriteHeader(statCode)
}

func UnsubscribeNamespaceNotifications(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	var (
		sub        Subscription
		commonName string
		err        error
		statCode   int
	)

	if err = json.NewDecoder(r.Body).Decode(&sub); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Errf("Namespace Notification Unregistration: %s",
			err.Error())
		return
	}

	commonName = r.TLS.PeerCertificates[0].Subject.CommonName

	vars := mux.Vars(r)

	statCode, err = removeSubscriptionToNamespace(commonName,
		vars["urn.namespace"], sub.Notifications)

	if err != nil {
		log.Errf("Namespace Notification Unregistration: %s",
			err.Error())
	}

	w.WriteHeader(statCode)
}

func UnsubscribeServiceNotifications(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	var (
		sub        Subscription
		commonName string
		err        error
		statCode   int
	)

	if err = json.NewDecoder(r.Body).Decode(&sub); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Errf("Service Notification Unregistration: %s", err.Error())
		return
	}

	commonName = r.TLS.PeerCertificates[0].Subject.CommonName

	vars := mux.Vars(r)

	statCode, err = removeSubscriptionToService(commonName,
		vars["urn.namespace"], vars["urn.id"], sub.Notifications)

	if err != nil {
		log.Errf("Service Notification Unregistration: %s",
			err.Error())
	}

	w.WriteHeader(statCode)
}
