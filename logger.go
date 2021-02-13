package ftauth

import "fmt"

// Logger allows printing logs in the mobile world.
type Logger interface {
	Debug(log string)
	Info(log string)
	Warn(log string)
	Error(log string)
}

// NullLogger is a Logger that discards all output.
var NullLogger = &LoggerImpl{nullLogger{}}

type nullLogger struct{}

func (nullLogger) Debug(log string) {}
func (nullLogger) Info(log string)  {}
func (nullLogger) Warn(log string)  {}
func (nullLogger) Error(log string) {}

// LoggerImpl wraps the Logger interface to define extra
// Go-specific helper functions. These functions cannot be
// part of the main interface but are helpful on the Go side.
type LoggerImpl struct {
	Logger
}

// Debugf formats according to fmt.Sprintf and calls log.Debug on the result.
func (log *LoggerImpl) Debugf(format string, a ...interface{}) {
	log.Debug(fmt.Sprintf(format, a...))
}

// Debugln formats according to fmt.Sprintln and calls log.Debug on the result.
func (log *LoggerImpl) Debugln(a ...interface{}) {
	log.Debug(fmt.Sprintln(a...))
}

// Infof formats according to fmt.Sprintf and calls log.Info on the result.
func (log *LoggerImpl) Infof(format string, a ...interface{}) {
	log.Info(fmt.Sprintf(format, a...))
}

// Infoln formats according to fmt.Sprintln and calls log.Info on the result.
func (log *LoggerImpl) Infoln(a ...interface{}) {
	log.Info(fmt.Sprintln(a...))
}

// Warnf formats according to fmt.Sprintf and calls log.Warn on the result.
func (log *LoggerImpl) Warnf(format string, a ...interface{}) {
	log.Warn(fmt.Sprintf(format, a...))
}

// Warnln formats according to fmt.Sprintln and calls log.Warn on the result.
func (log *LoggerImpl) Warnln(a ...interface{}) {
	log.Warn(fmt.Sprintln(a...))
}

// Errorf formats according to fmt.Sprintf and calls log.Error on the result.
func (log *LoggerImpl) Errorf(format string, a ...interface{}) {
	log.Error(fmt.Sprintf(format, a...))
}

// Errorln formats according to fmt.Sprintln and calls log.Error on the result.
func (log *LoggerImpl) Errorln(a ...interface{}) {
	log.Error(fmt.Sprintln(a...))
}
