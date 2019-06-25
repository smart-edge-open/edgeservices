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

package util

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Duration represents time.Duration with JSON Marshall/Unmarshal methods
type Duration struct {
	time.Duration
}

// UnmarshalJSON unmarshals the JSON data to Duration
func (t *Duration) UnmarshalJSON(data []byte) (err error) {
	t.Duration, err = time.ParseDuration(strings.Trim(string(data), `"`))
	return
}

// MarshalJSON marshals the Duration to JSON data
func (t Duration) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, t.String())), nil
}

// Heartbeat starts a goroutine that calls handler every interval
// and stops on ctx.Done(). If interval is not higher than 0
// the function does nothing
func Heartbeat(ctx context.Context, interval Duration, handler func()) {
	if interval.Duration > 0 {
		go func() {
			t := time.NewTicker(interval.Duration)
			for {
				select {
				case <-t.C:
					handler()
				case <-ctx.Done():
					t.Stop()
				}
			}
		}()
	}
}
