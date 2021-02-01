package ftauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"path"

	"github.com/ftauth/ftauth/pkg/model"
	"golang.org/x/oauth2/clientcredentials"
)

// Authorizer errors.
var (
	ErrUnsupportedClientType = errors.New("unsupported client type")
)

// Authorizer handles authorization with the server, invoking
// WebViews or HTTP requests as necessary to obtain an authenticated
// HTTP client, e.g. via the oauth2 package.
type Authorizer interface {
	Authorize() (*http.Client, error)
}

type defaultAuthorizer struct {
	config *clientcredentials.Config
}

func (auth *defaultAuthorizer) Authorize() (*http.Client, error) {
	ctx := context.TODO()
	return auth.config.Client(ctx), nil
}

// DefaultAuthorizer creates an Oauth2 confidential grant client.
// Public clients should use their platform's implementation.
func DefaultAuthorizer(config *ClientConfig) (Authorizer, error) {
	if config.ClientType == model.ClientTypePublic {
		return nil, ErrUnsupportedClientType
	}
	gatewayURL, err := url.Parse(config.GatewayURL)
	if err != nil {
		return nil, err
	}
	tokenURL := *gatewayURL
	tokenURL.Path = path.Join(gatewayURL.Path, "token")
	return &defaultAuthorizer{
		config: &clientcredentials.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Scopes:       config.Scopes,
			TokenURL:     tokenURL.String(),
		},
	}, nil
}
