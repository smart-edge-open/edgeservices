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

// SubscriberIds stores subscriber ids as a slice of strings
type SubscriberIds []string

// ConsumerSubscription stores namespace notification subscribers
// and a map of services and their subscribers
type ConsumerSubscription struct {
	namespaceSubscriptions SubscriberIds

	// map of producer id to slice of subscriber ids
	serviceSubscriptions map[string]SubscriberIds
}

// NotificationSubscriptions is a map of the namespace string merged
// with notification name and version to the consumer subscription struct
type NotificationSubscriptions map[string]ConsumerSubscription
