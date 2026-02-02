// Package log provides structured logging for the application.
package log

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

var logger zerolog.Logger

func init() {
	// Console writer for human-readable output
	output := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
		NoColor:    false,
	}

	logger = zerolog.New(output).
		With().
		Timestamp().
		Caller().
		Logger()

	// Set global log level from environment or default to Info
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if lvl := os.Getenv("LOG_LEVEL"); lvl != "" {
		if level, err := zerolog.ParseLevel(lvl); err == nil {
			zerolog.SetGlobalLevel(level)
		}
	}
}

// SetOutput sets the logger output destination
func SetOutput(w io.Writer) {
	logger = logger.Output(w)
}

// SetLevel sets the global log level
func SetLevel(level zerolog.Level) {
	zerolog.SetGlobalLevel(level)
}

// Debug logs a debug message
func Debug(msg string) {
	logger.Debug().Msg(msg)
}

// Debugf logs a formatted debug message
func Debugf(format string, args ...interface{}) {
	logger.Debug().Msgf(format, args...)
}

// Info logs an info message
func Info(msg string) {
	logger.Info().Msg(msg)
}

// Infof logs a formatted info message
func Infof(format string, args ...interface{}) {
	logger.Info().Msgf(format, args...)
}

// Warn logs a warning message
func Warn(msg string) {
	logger.Warn().Msg(msg)
}

// Warnf logs a formatted warning message
func Warnf(format string, args ...interface{}) {
	logger.Warn().Msgf(format, args...)
}

// Error logs an error message
func Error(msg string) {
	logger.Error().Msg(msg)
}

// Errorf logs a formatted error message
func Errorf(format string, args ...interface{}) {
	logger.Error().Msgf(format, args...)
}

// ErrorWithErr logs an error with the error object
func ErrorWithErr(err error, msg string) {
	logger.Error().Err(err).Msg(msg)
}

// Fatal logs a fatal message and exits
func Fatal(msg string) {
	logger.Fatal().Msg(msg)
}

// Fatalf logs a formatted fatal message and exits
func Fatalf(format string, args ...interface{}) {
	logger.Fatal().Msgf(format, args...)
}

// FatalWithErr logs a fatal error with the error object and exits
func FatalWithErr(err error, msg string) {
	logger.Fatal().Err(err).Msg(msg)
}

// WithField returns a logger with an additional field
func WithField(key string, value interface{}) *zerolog.Event {
	return logger.Info().Interface(key, value)
}

// WithFields returns a logger with multiple fields
func WithFields(fields map[string]interface{}) *zerolog.Event {
	event := logger.Info()
	for k, v := range fields {
		event = event.Interface(k, v)
	}
	return event
}
