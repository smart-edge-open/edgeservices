// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package log_test

import (
	"context"
	"log/syslog"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/otcshare/edgenode/common/log"
)

func TestSignalVerbosityChanges(t *testing.T) {
	defer func() { log.DefaultLogger = new(log.Logger) }()

	var (
		ctx, cancel = context.WithCancel(context.Background())
		pid         = os.Getpid()
		timeout     = time.After(time.Second)
	)
	defer cancel()
	log.SignalVerbosityChanges(ctx, log.DefaultLogger)

	// Decrease dynamically
	log.SetLevel(syslog.LOG_DEBUG)
	if err := syscall.Kill(pid, syscall.SIGUSR1); err != nil {
		t.Fatalf("got error sending USR1 signal to self: %v", err)
	}
WaitForDecrease:
	for {
		if lvl := log.GetLevel(); lvl == syslog.LOG_INFO {
			break WaitForDecrease
		}
		select {
		case <-timeout:
			t.Fatalf("timed out before signal decreased verbosity")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Increase dynamically
	log.SetLevel(syslog.LOG_EMERG)
	if err := syscall.Kill(pid, syscall.SIGUSR2); err != nil {
		t.Fatalf("got error sending USR2 signal to self: %v", err)
	}
WaitForIncrease:
	for {
		if lvl := log.GetLevel(); lvl == syslog.LOG_ALERT {
			break WaitForIncrease
		}
		select {
		case <-timeout:
			t.Fatalf("timed out before signal increased verbosity")
		case <-time.After(10 * time.Millisecond):
		}
	}
}
