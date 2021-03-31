// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package log

import (
	"fmt"
	"io"
	"log/syslog"
	"os"
	"path/filepath"
	"strings"
)

const (
	// DefaultLevel is the initial logging verbosity
	DefaultLevel = syslog.LOG_INFO
	// DefaultFacility is the default facility portion of the syslog priority.
	DefaultFacility = syslog.LOG_LOCAL0
)

const (
	severityMask = 0x07
	facilityMask = 0xf8
)

var (
	// DefaultLogger is the package-level logger that is used for all package
	// funcs.
	DefaultLogger = &Logger{}
)

var (
	svcName string
)

func init() {
	svcExe, _ := os.Executable()
	svcName = filepath.Base(svcExe)
}

// SetOutput changes the writer of local logs written by each logging func in
// addition to any remote syslog connection. If w is nil then os.Stderr will be
// used. If no non-remote logging is desired, set output to ioutil.Discard.
func SetOutput(w io.Writer) { DefaultLogger.SetOutput(w) }

// SetFacility alters the syslog facility used for logs. If the priority
// includes a verbosity level it will be ignored.
func SetFacility(p syslog.Priority) { DefaultLogger.SetFacility(p) }

// GetFacility returns the facility portion of the current syslog priority.
func GetFacility() syslog.Priority { return DefaultLogger.GetFacility() }

// ParseLevel parses provided syslog severity name
// into its integer(syslog.Priority) representation.
// Supported input values: emerg, emergency, alert, crit, critical, err, error,
// warn, warning, notice, info, information, debug.
// Input is parsed without case sensitivity.
func ParseLevel(prio string) (syslog.Priority, error) {
	switch strings.ToLower(prio) {
	case "emerg", "emergency":
		return syslog.LOG_EMERG, nil
	case "alert":
		return syslog.LOG_ALERT, nil
	case "crit", "critical":
		return syslog.LOG_CRIT, nil
	case "err", "error":
		return syslog.LOG_ERR, nil
	case "warning", "warn":
		return syslog.LOG_WARNING, nil
	case "notice":
		return syslog.LOG_NOTICE, nil
	case "info", "information":
		return syslog.LOG_INFO, nil
	case "debug":
		return syslog.LOG_DEBUG, nil
	default:
		var lvl syslog.Priority
		return lvl, fmt.Errorf("Invalid priority: %q", prio)
	}
}

// SetLevel alters the verbosity level that log will print at and below. It
// takes values syslog.LOG_EMERG...syslog.LOG_DEBUG. If the priority includes a
// facility it will be ignored.
func SetLevel(p syslog.Priority) { DefaultLogger.SetLevel(p) }

// GetLevel returns the verbosity level that log will print at and below. It
// can be compared to syslog.LOG_EMERG...syslog.LOG_DEBUG.
func GetLevel() syslog.Priority { return DefaultLogger.GetLevel() }

// ConnectSyslog connects to a remote syslog. If addr is an empty string, it
// will connect to the local syslog service.
func ConnectSyslog(addr string) error { return DefaultLogger.ConnectSyslog(addr) }

// DisconnectSyslog closes the connection to syslog.
func DisconnectSyslog() error { return DefaultLogger.DisconnectSyslog() }

// Print writes message with severity and set facility to output and syslog if connected.
func Print(p syslog.Priority, a ...interface{}) { DefaultLogger.Print(p, a...) }

// Println writes message with severity and set facility to output and syslog if connected.
func Println(p syslog.Priority, a ...interface{}) { DefaultLogger.Println(p, a...) }

// Printf writes message with severity and set facility to output and syslog if connected.
func Printf(p syslog.Priority, frmt string, a ...interface{}) { DefaultLogger.Printf(p, frmt, a...) }

// Debug writes DEBUG message to output and syslog if connected.
func Debug(a ...interface{}) { DefaultLogger.Debug(a...) }

// Debugln writes DEBUG message to output and syslog if connected.
func Debugln(a ...interface{}) { DefaultLogger.Debugln(a...) }

// Debugf writes formatted DEBUG message to output and syslog if connected.
func Debugf(frmt string, a ...interface{}) { DefaultLogger.Debugf(frmt, a...) }

// Info writes INFO message to output and syslog if connected.
func Info(a ...interface{}) { DefaultLogger.Info(a...) }

// Infoln writes INFO message to output and syslog if connected.
func Infoln(a ...interface{}) { DefaultLogger.Info(a...) }

// Infof writes formatted INFO message to output and syslog if connected.
func Infof(frmt string, a ...interface{}) { DefaultLogger.Infof(frmt, a...) }

// Notice writes NOTICE message to output and syslog if connected.
func Notice(a ...interface{}) { DefaultLogger.Notice(a...) }

// Noticeln writes NOTICE message to output and syslog if connected.
func Noticeln(a ...interface{}) { DefaultLogger.Notice(a...) }

// Noticef writes formatted NOTICE message to output and syslog if connected.
func Noticef(frmt string, a ...interface{}) { DefaultLogger.Noticef(frmt, a...) }

// Warning writes WARNING message to output and syslog if connected.
func Warning(a ...interface{}) { DefaultLogger.Warning(a...) }

// Warningln writes WARNING message to output and syslog if connected.
func Warningln(a ...interface{}) { DefaultLogger.Warning(a...) }

// Warningf writes formatted WARNING message to output and syslog if connected.
func Warningf(frmt string, a ...interface{}) { DefaultLogger.Warningf(frmt, a...) }

// Err writes ERROR message to output and syslog if connected.
func Err(a ...interface{}) { DefaultLogger.Err(a...) }

// Errln writes ERROR message to output and syslog if connected.
func Errln(a ...interface{}) { DefaultLogger.Err(a...) }

// Errf writes formatted ERROR message to output and syslog if connected.
func Errf(frmt string, a ...interface{}) { DefaultLogger.Errf(frmt, a...) }

// Crit writes CRITICAL message to output and syslog if connected.
func Crit(a ...interface{}) { DefaultLogger.Crit(a...) }

// Critln writes CRITICAL message to output and syslog if connected.
func Critln(a ...interface{}) { DefaultLogger.Crit(a...) }

// Critf writes formatted CRITICAL message to output and syslog if connected.
func Critf(frmt string, a ...interface{}) { DefaultLogger.Critf(frmt, a...) }

// Alert writes ALERT message to output and syslog if connected.
func Alert(a ...interface{}) { DefaultLogger.Alert(a...) }

// Alertln writes ALERT message to output and syslog if connected.
func Alertln(a ...interface{}) { DefaultLogger.Alert(a...) }

// Alertf writes formatted ALERT message to output and syslog if connected.
func Alertf(frmt string, a ...interface{}) { DefaultLogger.Alertf(frmt, a...) }

// Emerg writes EMERGENCY message to output and syslog if connected.
func Emerg(a ...interface{}) { DefaultLogger.Emerg(a...) }

// Emergln writes EMERGENCY message to output and syslog if connected.
func Emergln(a ...interface{}) { DefaultLogger.Emerg(a...) }

// Emergf writes formatted EMERGENCY message to output and syslog if connected.
func Emergf(frmt string, a ...interface{}) { DefaultLogger.Emergf(frmt, a...) }
