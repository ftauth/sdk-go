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
// WebViews or HTTP requests as necessary on a platform basis.
type Authorizer interface {
	// Authorize returns a URL through which the user must authenticate.
	// The client is responsible for listening to redirect steps and
	// capturing the query parameters for use with Exchange.
	Authorize() (string, error)

	// Exchange communicates with the FTAuth server, exchanging the
	// authorization code for an access + refresh token.
	Exchange(authResp *AuthorizationCodeResponse) (*http.Client, error)
}

type defaultAuthorizer struct {
	client *Client
	config *clientcredentials.Config
}

func (auth *defaultAuthorizer) Login() (*http.Client, error) {
	ctx := context.Background()
	return auth.config.Client(ctx), nil
}

func (auth *defaultAuthorizer) Authorize() (string, error) {
	return "", ErrUnsupportedClientType
}

func (auth *defaultAuthorizer) Exchange(authResp *AuthorizationCodeResponse) (*http.Client, error) {
	return nil, ErrUnsupportedClientType
}

// DefaultAuthorizer creates an Oauth2 confidential grant client.
// Public clients should use their platform's implementation.
func (client *Client) DefaultAuthorizer(config *ClientConfig) (Authorizer, error) {
	if config.ClientType == model.ClientTypePublic {
		return nil, ErrUnsupportedClientType
	}
	tokenURL, err := url.Parse(config.GatewayURL)
	if err != nil {
		return nil, err
	}
	tokenURL.Path = path.Join(tokenURL.Path, "token")
	return &defaultAuthorizer{
		client: client,
		config: &clientcredentials.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Scopes:       config.Scopes,
			TokenURL:     tokenURL.String(),
		},
	}, nil
}
