// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package log

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"os"
	"strings"
	"sync"
	"time"

	slog "github.com/smart-edge-open/edgeservices/common/log/syslog"
)

// Logger implements syslog logging funcs and can be connected to a syslog
// server.
type Logger struct {
	// Printer embeds all printing funcs. It should not be set manually.
	Printer
	once sync.Once

	outMu sync.RWMutex
	out   io.Writer

	priorityMu sync.RWMutex
	priority   syslog.Priority
	disabled   bool // level was explicitly set to EMERG
	isKernel   bool // facility was explicitly set to KERN

	syslogMu sync.RWMutex
	syslogW  *slog.Writer
}

// Must be called before any changing any writers or priority in order to
// ensure the embedded Printer operates correctly.
func (l *Logger) initPrinter() { l.Printer = l.WithFields(nil) }

// SetOutput changes the writer of local logs written by each logging func in
// addition to any remote syslog connection. If w is nil then os.Stderr will be
// used. If no non-remote logging is desired, set output to ioutil.Discard.
func (l *Logger) SetOutput(w io.Writer) {
	l.once.Do(l.initPrinter)

	l.outMu.Lock()
	l.out = w
	l.outMu.Unlock()
}

// SetFacility alters the syslog facility used for logs. If the priority
// includes a verbosity level it will be ignored.
func (l *Logger) SetFacility(p syslog.Priority) {
	l.once.Do(l.initPrinter)

	if fac := (p & facilityMask); fac > syslog.LOG_LOCAL7 {
		panic("invalid facility")
	}

	l.priorityMu.Lock()
	defer l.priorityMu.Unlock()

	l.priority = syslevel(l.getLevel(), p)
	l.isKernel = (p & facilityMask) == syslog.LOG_KERN
}

// GetFacility returns the facility portion of the current syslog priority.
func (l *Logger) GetFacility() syslog.Priority {
	l.priorityMu.RLock()
	defer l.priorityMu.RUnlock()
	return l.getFacility()
}

// Only call with a read lock on the priority mutex
func (l *Logger) getFacility() syslog.Priority {
	if fac := (l.priority & facilityMask); fac == syslog.LOG_KERN && !l.isKernel {
		return DefaultFacility
	}
	return l.priority & facilityMask
}

// SetLevel alters the verbosity level that log will print at and below. It
// takes values syslog.LOG_EMERG...syslog.LOG_DEBUG. If the priority includes a
// facility it will be ignored.
func (l *Logger) SetLevel(p syslog.Priority) {
	l.once.Do(l.initPrinter)

	l.priorityMu.Lock()
	defer l.priorityMu.Unlock()
	l.setLevel(p)
}

// Only call with a read lock on the priority mutex
func (l *Logger) setLevel(p syslog.Priority) {
	if lvl := (p & severityMask); lvl > syslog.LOG_DEBUG {
		p = syslevel(syslog.LOG_DEBUG, p)
	} else if lvl < syslog.LOG_EMERG {
		p = syslevel(syslog.LOG_EMERG, p)
	}
	l.priority = syslevel(p, l.getFacility())
	l.disabled = (p & severityMask) == syslog.LOG_EMERG
}

// GetLevel returns the verbosity level that log will print at and below. It
// can be compared to syslog.LOG_EMERG...syslog.LOG_DEBUG.
func (l *Logger) GetLevel() syslog.Priority {
	l.priorityMu.RLock()
	defer l.priorityMu.RUnlock()
	return l.getLevel()
}

// Only call with a read lock on the priority mutex
func (l *Logger) getLevel() syslog.Priority {
	lvl := (l.priority & severityMask)
	if lvl == syslog.LOG_EMERG && !l.disabled {
		return DefaultLevel
	}
	return lvl
}

// ConnectSyslog connects to a remote syslog. If addr is an empty string, it
// will connect to the local syslog service.
func (l *Logger) ConnectSyslog(addr string) error {
	net := "udp"
	if addr == "" {
		net = ""
	}
	return l.connect(net, addr, nil, slog.DialTLS)
}

// ConnectSyslogTLS connects to a remote syslog, performing a TLS client
// handshake. This is always done over TCP and the addr cannot be empty (in an
// attempt to connect to the local syslog service).
func (l *Logger) ConnectSyslogTLS(addr string, conf *tls.Config) error {
	return l.connect("tcp", addr, conf, slog.DialTLS)
}

func (l *Logger) connect(net, addr string, conf *tls.Config,
	dial func(string, string, syslog.Priority, string, *tls.Config) (*slog.Writer, error)) error {
	l.once.Do(l.initPrinter)

	l.syslogMu.Lock()
	defer l.syslogMu.Unlock()

	if l.syslogW != nil {
		// TODO(ben): handle replacing a syslog connection
		return fmt.Errorf("syslog already dialed")
	}

	// Get syslog facility and combine with INFO level default logging.
	// DEBUG will be used for syslogW.Write, which won't be called.
	l.priorityMu.RLock()
	priority := syslevel(syslog.LOG_DEBUG, l.getFacility())
	l.priorityMu.RUnlock()

	// Dial syslog
	var err error
	l.syslogW, err = dial(net, addr, priority, svcName, conf)
	return err
}

// DisconnectSyslog closes the connection to syslog.
func (l *Logger) DisconnectSyslog() error {
	l.syslogMu.Lock()
	defer l.syslogMu.Unlock()

	if l.syslogW == nil {
		return nil
	}
	err := l.syslogW.Close()
	l.syslogW = nil
	return err
}

func (l *Logger) format(fields map[string]interface{}) func(string, ...interface{}) string {
	var tags []string
	for key, value := range fields {
		field := "[" + key + "]"
		if value != nil {
			field = fmt.Sprintf("[%s=%v]", key, value)
		}
		tags = append(tags, field)
	}
	data := strings.Join(tags, " ")
	if len(data) > 0 {
		data += " "
	}

	return func(frmt string, a ...interface{}) string {
		if frmt == "" {
			return data + fmt.Sprint(a...)
		}
		return data + fmt.Sprintf(frmt, a...)
	}
}

func (l *Logger) write(p syslog.Priority, msg string) {
	// Bail if level is too low
	if (p & severityMask) > l.GetLevel() {
		return
	}

	// Write to local
	l.outMu.RLock()
	out := l.out
	l.outMu.RUnlock()
	if out == nil {
		out = os.Stderr
	}
	// ensure msg ends in a \n
	nl := ""
	if !strings.HasSuffix(msg, "\n") {
		nl = "\n"
	}
	_, err := fmt.Fprintf(out, "<%d>%s %s[%d]: %s%s",
		syslevel(p, l.priority), time.Now().Format(time.Stamp), svcName, os.Getpid(), msg, nl)
	if err != nil {
		log.Printf("error writing to local log: %s", err)
	}
}

func (l *Logger) writeSyslog(p syslog.Priority, msg string) { //nolint: gocyclo
	// ensure msg ends in a \n
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}

	l.syslogMu.RLock()
	syslogW := l.syslogW
	l.syslogMu.RUnlock()
	if syslogW == nil {
		return
	}

	var err error
	switch p & severityMask {
	case syslog.LOG_DEBUG:
		err = syslogW.Debug(msg)
	case syslog.LOG_INFO:
		err = syslogW.Info(msg)
	case syslog.LOG_NOTICE:
		err = syslogW.Notice(msg)
	case syslog.LOG_WARNING:
		err = syslogW.Warning(msg)
	case syslog.LOG_ERR:
		err = syslogW.Err(msg)
	case syslog.LOG_CRIT:
		err = syslogW.Crit(msg)
	case syslog.LOG_ALERT:
		err = syslogW.Alert(msg)
	case syslog.LOG_EMERG:
		err = syslogW.Emerg(msg)
	default:
		panic("unknown log level")
	}
	if err != nil {
		// Get backup output to write to
		l.outMu.RLock()
		out := l.out
		l.outMu.RUnlock()
		if out == nil {
			out = os.Stderr
		}

		// Write error to backup writer
		errmsg := strings.TrimSuffix("error writing to syslog: "+err.Error(), "\n") + "\n"
		_, err2 := fmt.Fprintf(out, "<%d>%s %s[%d]: %s",
			syslevel(p, l.priority), time.Now().Format(time.RFC3339Nano), svcName, os.Getpid(), errmsg)
		if err2 != nil {
			log.Printf("error writing to local log about being unable to write to syslog:\n%s\n\n%s",
				err, err2)
		}
	}
}

// Helper func to combine a level with a facility into a syslog priority.
func syslevel(lvl, fac syslog.Priority) syslog.Priority {
	return (lvl & severityMask) | (fac & facilityMask)
}
