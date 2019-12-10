// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eaa

import (
	"context"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// Route describes traffic routing
type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

// Routes represents a routing table
type Routes []Route

// NewEaaRouter initializes EAA router
func NewEaaRouter(eaaCtx *eaaContext) *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	for _, route := range eaaRoutes {
		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(route.HandlerFunc)
	}
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(
				r.Context(),
				contextKey("appliance-ctx"),
				eaaCtx)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	return router
}

// NewAuthRouter initializes EAA Auth router
func NewAuthRouter(eaaCtx *eaaContext) *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	for _, route := range authRoutes {
		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(route.HandlerFunc)
	}
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(
				r.Context(),
				contextKey("appliance-ctx"),
				eaaCtx)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	return router
}

var authRoutes = Routes{
	Route{
		"RequestCredentials",
		strings.ToUpper("Post"),
		"/auth",
		RequestCredentials,
	},
}

var eaaRoutes = Routes{
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
