// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eaa

import "encoding/json"

// NotificationDescriptor describes a type used in EAA API
type NotificationDescriptor struct {
	// Name of notification
	Name string `json:"name,omitempty"`
	// Version of notification
	Version string `json:"version,omitempty"`
	// Human readable description of notification
	Description string `json:"description,omitempty"`
}

// NotificationFromProducer describes a type used in EAA API
type NotificationFromProducer struct {
	// Name of notification
	Name string `json:"name,omitempty"`
	// Version of notification
	Version string `json:"version,omitempty"`
	// The payload can be any JSON object with a name
	// and version-specific schema.
	Payload json.RawMessage `json:"payload,omitempty"`
}

// NotificationToConsumer describes a type used in EAA API
type NotificationToConsumer struct {
	// Name of notification
	Name string `json:"name,omitempty"`
	// Version of notification
	Version string `json:"version,omitempty"`
	// The payload can be any JSON object with a name
	// and version-specific schema.
	Payload json.RawMessage `json:"payload,omitempty"`
	// URN of the producer
	URN URN `json:"producer,omitempty"`
}

// ServiceList JSON struct
type ServiceList struct {
	Services []Service `json:"services,omitempty"`
}

// Service JSON struct
type Service struct {
	URN           *URN                     `json:"urn,omitempty"`
	Description   string                   `json:"description,omitempty"`
	EndpointURI   string                   `json:"endpoint_uri,omitempty"`
	Status        string                   `json:"status,omitempty"`
	Notifications []NotificationDescriptor `json:"notifications,omitempty"`
}

// SubscriptionList JSON struct
type SubscriptionList struct {
	Subscriptions []Subscription `json:"subscriptions,omitempty"`
}

// Subscription describes a type used in EAA API
type Subscription struct {

	// The name of the producer app. The unique ID is optional for
	// subscribing and if not given will subscribe to any producer in the
	// namespace.
	URN *URN `json:"urn,omitempty"`

	// The list of all notification types registered by all producers in
	// this namespace.
	Notifications []NotificationDescriptor `json:"notifications,omitempty"`
}

// URN describes a type used in EAA API
type URN struct {

	// The per-namespace unique portion of the URN that when appended to
	// the namespace with a separator forms the complete URN.
	ID string `json:"id,omitempty"`

	// The non-unique portion of the URN that identifies the class excluding
	// a trailing separator.
	Namespace string `json:"namespace,omitempty"`
}
