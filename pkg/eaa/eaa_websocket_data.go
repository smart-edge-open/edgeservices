// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eaa

import (
	"github.com/gorilla/websocket"
)

// ConsumerConnection stores websocket connection of a consumer
type ConsumerConnection struct {

	// The details of the websocket connection between the agent and the
	// consumer app.
	connection *websocket.Conn
}
