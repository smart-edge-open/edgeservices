package eaa

type NotificationDescriptor struct {
	Name string `json:"name,omitempty"`

	Version string `json:"version,omitempty"`

	Description string `json:"description,omitempty"`
}

type Notification struct {
	Name string `json:"name,omitempty"`

	Version string `json:"version,omitempty"`

	// The payload can be any JSON object with a name
	// and version-specific schema.
	Payload *RawJSONObject `json:"payload,omitempty"`
}

type RawJSONObject struct {
}

type ServiceList struct {
	Services []Service `json:"services,omitempty"`
}

type Service struct {
	Urn *Urn `json:"urn,omitempty"`

	Description string `json:"description,omitempty"`

	EndpointURI string `json:"endpoint_uri,omitempty"`

	Status string `json:"status,omitempty"`

	Notifications []NotificationDescriptor `json:"notifications,omitempty"`
}

type SubscriptionList struct {
	Subscriptions []Subscription `json:"subscriptions,omitempty"`
}

type Subscription struct {

	// The name of the producer app. The unique ID is optional for
	// subscribing and if not given will subscribe to any producer in the
	// namespace.
	Urn *Urn `json:"urn,omitempty"`

	// The list of all notification types registered by all producers in
	// this namespace.
	Notifications []NotificationDescriptor `json:"notifications,omitempty"`
}

type Urn struct {

	// The per-namespace unique portion of the URN that when appended to
	// the namespace with a separator forms the complete URN.
	ID string `json:"id,omitempty"`

	// The non-unique portion of the URN that identifies the class excluding
	// a trailing separator.
	Namespace string `json:"namespace,omitempty"`
}
