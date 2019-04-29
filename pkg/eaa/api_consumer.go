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
	"github.com/gorilla/websocket"
	"net/http"
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
	if appID == r.Host {
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
