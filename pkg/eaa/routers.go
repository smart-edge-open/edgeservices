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
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

type Routes []Route

func NewRouter() *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	for _, route := range routes {
		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(route.HandlerFunc)
	}

	return router
}

func Index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello World!")
}

var routes = Routes{
	Route{
		"Index",
		"GET",
		"/",
		Index,
	},

	Route{
		"DeregisterApplication",
		strings.ToUpper("Delete"),
		"/services",
		DeregisterApplication,
	},

	Route{
		"GetNotifications",
		strings.ToUpper("Get"),
		"/notifications",
		GetNotifications,
	},

	Route{
		"GetServices",
		strings.ToUpper("Get"),
		"/services",
		GetServices,
	},

	Route{
		"GetSubscriptions",
		strings.ToUpper("Get"),
		"/subscriptions",
		GetSubscriptions,
	},

	Route{
		"PushNotificationToSubscribers",
		strings.ToUpper("Post"),
		"/notifications",
		PushNotificationToSubscribers,
	},

	Route{
		"RegisterApplication",
		strings.ToUpper("Post"),
		"/services",
		RegisterApplication,
	},

	Route{
		"SubscribeNamespaceNotifications",
		strings.ToUpper("Post"),
		"/subscriptions/{urn.namespace}",
		SubscribeNamespaceNotifications,
	},

	Route{
		"SubscribeServiceNotifications",
		strings.ToUpper("Post"),
		"/subscriptions/{urn.namespace}/{urn.id}",
		SubscribeServiceNotifications,
	},

	Route{
		"UnsubscribeAllNotifications",
		strings.ToUpper("Delete"),
		"/subscriptions",
		UnsubscribeAllNotifications,
	},

	Route{
		"UnsubscribeNamespaceNotifications",
		strings.ToUpper("Delete"),
		"/subscriptions/{urn.namespace}",
		UnsubscribeNamespaceNotifications,
	},

	Route{
		"UnsubscribeServiceNotifications",
		strings.ToUpper("Delete"),
		"/subscriptions/{urn.namespace}/{urn.id}",
		UnsubscribeServiceNotifications,
	},
}
