package ftauth

import (
	"fmt"
	"net/url"

	"github.com/ftauth/ftauth/pkg/jwt"
	"github.com/ftauth/ftauth/pkg/model"
)

// ClientConfig holds configuration information for the FTAuth client.
type ClientConfig struct {
	GatewayURL   string           `json:"gateway_url"`
	ClientID     string           `json:"client_id"`
	ClientSecret string           `json:"client_secret"`
	ClientType   model.ClientType `json:"client_type"`
	RedirectURI  string           `json:"redirect_uri"`
	Scopes       []string         `json:"scopes"`
	Timeout      uint             `json:"timeout"`
	keySet       *jwt.KeySet      `json:"-"`
}

// Valid returns an error if there are missing or invalid fields,
// otherwise nil.
func (c *ClientConfig) Valid() error {
	if c.GatewayURL == "" {
		return errInvalidField("gateway_url", "empty")
	}
	uri, err := url.Parse(c.GatewayURL)
	if err != nil {
		return errInvalidField("gateway_url", err.Error())
	}
	if uri.Scheme == "http" && uri.Hostname() != "localhost" {
		return errInvalidField("gateway_url", "http scheme unsupported")
	}
	if c.ClientID == "" {
		return errInvalidField("client_id", "empty")
	}
	if c.ClientType == "" {
		return errInvalidField("client_type", "empty")
	}
	if c.ClientType == model.ClientTypeConfidential {
		if c.ClientSecret == "" {
			return errInvalidField("client_secret", "missing secret")
		}
	}
	redirectURI, err := url.Parse(c.RedirectURI)
	if err != nil {
		return errInvalidField("redirect_uri", err.Error())
	}
	if redirectURI.Scheme == "http" && redirectURI.Hostname() != "localhost" {
		return errInvalidField("redirect_uri", "http scheme unsupported")
	}
	if len(c.Scopes) == 0 {
		return errInvalidField("scopes", "empty")
	}

	return nil
}

func errInvalidField(field, reason string) error {
	return fmt.Errorf("invalid %s: %s", field, reason)
}
