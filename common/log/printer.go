// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package log

import (
	"fmt"
	"log/syslog"
)

// Printer formats and writes logs conditionally based on the current priority
// level.
type Printer struct {
	Format      func(frmt string, a ...interface{}) string
	Write       func(lvl syslog.Priority, msg string)
	WriteSyslog func(lvl syslog.Priority, msg string)
}

// WithField returns a Printer tagged with a single field.
func (l *Logger) WithField(key string, value interface{}) Printer {
	return l.WithFields(map[string]interface{}{key: value})
}

// WithFields returns a Printer tagged with multiple fields.
func (l *Logger) WithFields(kvs map[string]interface{}) Printer {
	return Printer{
		Format:      l.format(kvs),
		Write:       l.write,
		WriteSyslog: l.writeSyslog,
	}
}

// Printf writes message with severity and set facility to output and syslog if connected.
func (p Printer) Printf(lvl syslog.Priority, frmt string, a ...interface{}) {
	// get formatter and writer with defaults
	formatter := p.Format
	if formatter == nil {
		if frmt == "" {
			formatter = func(_ string, a ...interface{}) string { return fmt.Sprint(a...) }
		} else {
			formatter = fmt.Sprintf
		}
	}
	write := p.Write
	if write == nil {
		write = (&Logger{priority: lvl}).write
	}
	writeSyslog := p.WriteSyslog
	if writeSyslog == nil {
		writeSyslog = (&Logger{}).writeSyslog
	}

	// write formatted string
	msg := formatter(frmt, a...)
	write(lvl, msg)
	writeSyslog(lvl, msg)
}

// Print writes message with severity and set facility to output and syslog if connected.
func (p Printer) Print(lvl syslog.Priority, a ...interface{}) { p.Printf(lvl, "", a...) }

// Println writes message with severity and set facility to output and syslog if connected.
func (p Printer) Println(lvl syslog.Priority, a ...interface{}) { p.Print(lvl, append(a, "\n")...) }

// Debug writes DEBUG message to output and syslog if connected.
func (p Printer) Debug(a ...interface{}) { p.Debugf("", a...) }

// Debugln writes DEBUG message to output and syslog if connected.
func (p Printer) Debugln(a ...interface{}) { p.Debugf("", a...) }

// Debugf writes formatted DEBUG message to output and syslog if connected.
func (p Printer) Debugf(frmt string, a ...interface{}) { p.Printf(syslog.LOG_DEBUG, frmt, a...) }

// Info writes INFO message to output and syslog if connected.
func (p Printer) Info(a ...interface{}) { p.Infof("", a...) }

// Infoln writes INFO message to output and syslog if connected.
func (p Printer) Infoln(a ...interface{}) { p.Infof("", a...) }

// Infof writes formatted INFO message to output and syslog if connected.
func (p Printer) Infof(frmt string, a ...interface{}) { p.Printf(syslog.LOG_INFO, frmt, a...) }

// Notice writes NOTICE message to output and syslog if connected.
func (p Printer) Notice(a ...interface{}) { p.Noticef("", a...) }

// Noticeln writes NOTICE message to output and syslog if connected.
func (p Printer) Noticeln(a ...interface{}) { p.Noticef("", a...) }

// Noticef writes formatted NOTICE message to output and syslog if connected.
func (p Printer) Noticef(frmt string, a ...interface{}) { p.Printf(syslog.LOG_NOTICE, frmt, a...) }

// Warning writes WARNING message to output and syslog if connected.
func (p Printer) Warning(a ...interface{}) { p.Warningf("", a...) }

// Warningln writes WARNING message to output and syslog if connected.
func (p Printer) Warningln(a ...interface{}) { p.Warningf("", a...) }

// Warningf writes formatted WARNING message to output and syslog if connected.
func (p Printer) Warningf(frmt string, a ...interface{}) { p.Printf(syslog.LOG_WARNING, frmt, a...) }

// Err writes ERROR message to output and syslog if connected.
func (p Printer) Err(a ...interface{}) { p.Errf("", a...) }

// Errln writes ERROR message to output and syslog if connected.
func (p Printer) Errln(a ...interface{}) { p.Errf("", a...) }

// Errf writes formatted ERROR message to output and syslog if connected.
func (p Printer) Errf(frmt string, a ...interface{}) { p.Printf(syslog.LOG_ERR, frmt, a...) }

// Crit writes CRITICAL message to output and syslog if connected.
func (p Printer) Crit(a ...interface{}) { p.Critf("", a...) }

// Critln writes CRITICAL message to output and syslog if connected.
func (p Printer) Critln(a ...interface{}) { p.Critf("", a...) }

// Critf writes formatted CRITICAL message to output and syslog if connected.
func (p Printer) Critf(frmt string, a ...interface{}) { p.Printf(syslog.LOG_CRIT, frmt, a...) }

// Alert writes ALERT message to output and syslog if connected.
func (p Printer) Alert(a ...interface{}) { p.Alertf("", a...) }

// Alertln writes ALERT message to output and syslog if connected.
func (p Printer) Alertln(a ...interface{}) { p.Alertf("", a...) }

// Alertf writes formatted ALERT message to output and syslog if connected.
func (p Printer) Alertf(frmt string, a ...interface{}) { p.Printf(syslog.LOG_ALERT, frmt, a...) }

// Emerg writes EMERGENCY message to output and syslog if connected.
func (p Printer) Emerg(a ...interface{}) { p.Emergf("", a...) }

// Emergln writes EMERGENCY message to output and syslog if connected.
func (p Printer) Emergln(a ...interface{}) { p.Emergf("", a...) }

// Emergf writes formatted EMERGENCY message to output and syslog if connected.
func (p Printer) Emergf(frmt string, a ...interface{}) { p.Printf(syslog.LOG_EMERG, frmt, a...) }
