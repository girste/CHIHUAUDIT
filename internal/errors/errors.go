// Package errors provides standardized error handling for chihuaudit.
// It defines sentinel errors and utilities for error wrapping with context.
package errors

import (
	stderrors "errors"
	"fmt"
)

// Sentinel errors for common failure scenarios
var (
	// ErrAnalyzerFailed indicates an analyzer failed to complete
	ErrAnalyzerFailed = stderrors.New("analyzer failed")

	// ErrTimeoutExceeded indicates a command or operation exceeded its timeout
	ErrTimeoutExceeded = stderrors.New("timeout exceeded")

	// ErrPermissionDenied indicates insufficient permissions
	ErrPermissionDenied = stderrors.New("permission denied")

	// ErrCommandNotFound indicates a required command is not available
	ErrCommandNotFound = stderrors.New("command not found")

	// ErrInvalidConfig indicates configuration is invalid or incomplete
	ErrInvalidConfig = stderrors.New("invalid configuration")

	// ErrNetworkFailure indicates a network operation failed
	ErrNetworkFailure = stderrors.New("network failure")

	// ErrDatabaseConnection indicates database connection failed
	ErrDatabaseConnection = stderrors.New("database connection failed")

	// ErrInvalidInput indicates user input is invalid
	ErrInvalidInput = stderrors.New("invalid input")

	// ErrNotFound indicates a requested resource was not found
	ErrNotFound = stderrors.New("not found")

	// ErrAlreadyExists indicates a resource already exists
	ErrAlreadyExists = stderrors.New("already exists")

	// ErrServiceUnavailable indicates an external service is unavailable
	ErrServiceUnavailable = stderrors.New("service unavailable")

	// ErrParseFailure indicates parsing failed
	ErrParseFailure = stderrors.New("parse failure")

	// ErrFileOperation indicates a file operation failed
	ErrFileOperation = stderrors.New("file operation failed")
)

// Wrap wraps an error with context message and preserves the underlying error chain.
// Use this to add context while maintaining error identity for stderrors.Is checks.
func Wrap(err error, format string, args ...interface{}) error {
	if err == nil {
		return nil
	}
	msg := fmt.Sprintf(format, args...)
	return fmt.Errorf("%s: %w", msg, err)
}

// New creates a new error with formatted message.
// Use this for new errors that don't wrap existing errors.
func New(format string, args ...interface{}) error {
	return fmt.Errorf(format, args...)
}

// Is reports whether any error in err's chain matches target.
// This is a convenience wrapper around stderrors.Is.
func Is(err, target error) bool {
	return stderrors.Is(err, target)
}

// As finds the first error in err's chain that matches target type.
// This is a convenience wrapper around stderrors.As.
func As(err error, target interface{}) bool {
	return stderrors.As(err, target)
}
