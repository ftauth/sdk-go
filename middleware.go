package ftauth

import (
	"errors"

	fthttp "github.com/ftauth/ftauth/pkg/http"
)

// NewMiddleware creates a middleware factory for FTAuth verification.
func NewMiddleware(config *Config) (*fthttp.Middleware, error) {
	if config.ClientConfig.keySet == nil || len(config.ClientConfig.keySet.Keys) == 0 {
		return nil, errors.New("empty keyset")
	}
	return fthttp.NewMiddleware(config.ClientConfig.keySet)
}
