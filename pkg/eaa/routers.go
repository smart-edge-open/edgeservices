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
		handler := Logger(route.HandlerFunc, route.Name)

		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(handler)
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
		"SubscribeNotifications",
		strings.ToUpper("Post"),
		"/subscriptions/{urn.namespace}",
		SubscribeNotifications,
	},

	Route{
		"SubscribeNotifications2",
		strings.ToUpper("Post"),
		"/subscriptions/{urn.namespace}/{urn.id}",
		SubscribeNotifications2,
	},

	Route{
		"UnsubscribeAllNotifications",
		strings.ToUpper("Delete"),
		"/subscriptions",
		UnsubscribeAllNotifications,
	},

	Route{
		"UnsubscribeNotifications",
		strings.ToUpper("Delete"),
		"/subscriptions/{urn.namespace}",
		UnsubscribeNotifications,
	},

	Route{
		"UnsubscribeNotifications2",
		strings.ToUpper("Delete"),
		"/subscriptions/{urn.namespace}/{urn.id}",
		UnsubscribeNotifications2,
	},
}
