// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package log

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// SignalVerbosityChanges captures SIGUSR1 and SIGUSR2 and decreases and
// increases verbosity on each signal, respectively.
//
// This function spawns a goroutine in order to make it safe to send a USR1 or
// USR2 signal as soon as the function has returned.
func SignalVerbosityChanges(ctx context.Context, l *Logger) {
	decC := make(chan os.Signal, 1)
	incC := make(chan os.Signal, 1)
	signal.Notify(decC, syscall.SIGUSR1)
	signal.Notify(incC, syscall.SIGUSR2)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-decC:
				l.priorityMu.Lock()
				l.setLevel(l.getLevel() - 1)
				l.priorityMu.Unlock()
			case <-incC:
				l.priorityMu.Lock()
				l.setLevel(l.getLevel() + 1)
				l.priorityMu.Unlock()
			}
		}
	}()
}
