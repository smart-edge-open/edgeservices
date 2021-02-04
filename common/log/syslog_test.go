// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package log_test

import (
	"bufio"
	"bytes"
	"os/exec"
	"regexp"
	"runtime"
	"testing"
	"time"

	"github.com/otcshare/edgenode/common/log"
)

func TestLoggerConnectSyslogLocal(t *testing.T) { // nolint: gocyclo
	var buf bytes.Buffer
	log := new(log.Logger)
	log.SetOutput(&buf)

	// Connect to local syslog instance
	if err := log.ConnectSyslog(""); err != nil {
		t.Fatalf("error connecting to local syslog: %v", err)
	}
	defer func() { _ = log.DisconnectSyslog() }()

	// Determine local syslog file
	var path string
	switch runtime.GOOS {
	case "linux":
		path = "/var/log/syslog"
	case "darwin":
		path = "/var/log/system.log"
	default:
		t.Fatal("unsupported OS")
	}

	// Start tailing local syslog file
	cmd := exec.Command("tail", "-n0", "-f", path)
	tailOut, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("error tailing %s: %v", path, err)
	}
	defer tailOut.Close()
	if err := cmd.Start(); err != nil {
		t.Fatalf("error running 'tail -f %s': %v", path, err)
	}
	time.Sleep(10 * time.Millisecond) // must wait long enough for tail to seek to end of file

	// Write an ERROR message (must be high enough priority for system)
	msg := "otcshare/edgenode/common syslog test"
	matcher := regexp.MustCompile(": " + msg + "\\n$")
	log.Err(msg)

	// Exect message to be written to output
	if !matcher.MatchString(buf.String()) {
		t.Errorf("expected %q to end with '%s\\n'", buf.String(), msg)
	}

	// Expect message to be written to local syslog file
	var (
		timeout  = time.After(time.Second)
		nextLine = make(chan string, 1)
		errC     = make(chan error, 1)
		tailLog  = bufio.NewReader(tailOut)
	)
	go func() {
		for {
			line, err := tailLog.ReadString('\n')
			if err != nil {
				errC <- err
				return
			}
			nextLine <- line
		}
	}()
WaitForWrite:
	for {
		select {
		case <-timeout:
			t.Fatalf("timed out waiting for message matching regexp %q from syslog", matcher)
		case err := <-errC:
			t.Fatalf("error reading 'tail -f %s': %v", path, err)
		case line := <-nextLine:
			t.Logf("%q\n", line)
			if matcher.MatchString(line) {
				break WaitForWrite
			}
		}
	}

	// Wait for tail to exit
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}
