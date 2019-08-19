package devdeploy

import (
	"github.com/pkg/errors"
)

var (
	// ErrInvalidFunction occurs when no config can be determined for a function.
	ErrInvalidFunction = errors.New("Invalid function")

	// ErrInvalidService occurs when no config can be determined for a service.
	ErrInvalidService = errors.New("Invalid service")
)
