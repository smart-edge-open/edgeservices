// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

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
