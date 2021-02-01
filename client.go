package ftauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/ftauth/ftauth/pkg/jwt"
	"golang.org/x/oauth2"
)

// Common errors.
var (
	ErrNotAuthenticated = errors.New("the client is not authenticated")
	ErrNoRefreshToken   = errors.New("no refresh token")
	ErrInvalidKeyStore  = errors.New("invalid keystore")
)

// Common keys.
var (
	KeyAccessToken  = []byte("access_token")
	KeyRefreshToken = []byte("refresh_token")
	keyPrivateKey   = []byte("private_key")
)

// Client communicates with HTTP services on behalf
// of an authenticated user.
type Client struct {
	accessToken  *jwt.Token
	refreshToken *jwt.Token
	privateKey   *jwt.Key
	httpClient   *http.Client
	Config       *ClientConfig
	KeyStore     KeyStore
}

// if config.Authorizer == nil {
// 	auth, err := DefaultAuthorizer(config.ClientConfig)
// 	if err != nil {
// 		return nil, err
// 	}
// 	config.Authorizer = auth
// }

// Config holds options for configuring the client.
// Use DefaultOptions if unsure.
type Config struct {
	KeyStore     KeyStore
	ClientConfig *ClientConfig
}

// NewClient creates a new FTAuth client with the given options.
// Use DefaultOptions if unsure.
func NewClient(config *Config) (*Client, error) {
	if config.KeyStore == nil {
		return nil, ErrInvalidKeyStore
	}

	c := &Client{
		KeyStore: config.KeyStore,
		Config:   config.ClientConfig,
	}

	err := config.KeyStore.Save(KeyAccessToken, []byte("abcdefg"))
	if err != nil {
		return nil, err
	}

	err = c.Initialize()
	if err != nil {
		return nil, err
	}

	return c, nil
}

func isErrKeyNotFound(err error) bool {
	if keystoreErr, ok := err.(*KeyStoreError); ok {
		return keystoreErr.Code == KeyStoreErrorCodeKey
	}
	return false
}

// Initialize loads the client with cached values from the KeyStore.
func (c *Client) Initialize() error {
	var validAccessToken bool

	accessJWT, err := c.KeyStore.Get(KeyAccessToken)
	if err == nil && !isErrKeyNotFound(err) {
		return err
	}
	if accessJWT != nil {
		accessToken, err := jwt.Decode(string(accessJWT))
		if err != nil {
			return err
		}
		if accessToken.IsExpired() {
			c.accessToken = accessToken
			validAccessToken = true
		}
	}

	if validAccessToken {
		refreshJWT, err := c.KeyStore.Get(KeyRefreshToken)
		if err == nil && !isErrKeyNotFound(err) {
			return err
		}
		if refreshJWT != nil {
			c.refreshToken, err = jwt.Decode(string(refreshJWT))
			if err != nil {
				return err
			}
		}
	}

	privateJWK, err := c.KeyStore.Get(keyPrivateKey)
	if err == nil && !isErrKeyNotFound(err) {
		return err
	}
	if privateJWK != nil {
		c.privateKey, err = jwt.ParseJWK(string(privateJWK))
		if err != nil {
			return err
		}
	} else {
		privateKey, err := generatePrivateKey()
		if err != nil {
			return err
		}
		c.privateKey, err = jwt.NewJWKFromRSAPrivateKey(privateKey)
		if err != nil {
			return err
		}
		b, err := json.Marshal(c.privateKey)
		if err != nil {
			return err
		}
		err = c.KeyStore.Save(keyPrivateKey, b)
		if err != nil {
			return err
		}
	}

	return nil
}

func generatePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// Token implements TokenSource for the oauth2 package.
func (c *Client) Token() (*oauth2.Token, error) {
	if c.accessToken == nil || c.refreshToken == nil {
		return nil, ErrNotAuthenticated
	}
	accessJWT, err := c.accessToken.Raw()
	if err != nil {
		return nil, err
	}
	refreshJWT, err := c.refreshToken.Raw()
	if err != nil {
		return nil, err
	}
	return &oauth2.Token{
		AccessToken:  accessJWT,
		RefreshToken: refreshJWT,
		Expiry:       time.Unix(c.accessToken.Claims.ExpirationTime, 0),
	}, nil
}

// IsAuthenticated returns true if the user has an authenticated HTTP client.
func (c *Client) IsAuthenticated() bool {
	if c.httpClient == nil {
		return false
	}
	return true
}

// Request performs an HTTP request on behalf of the authenticated user,
// automatically refreshing credentials as needed.
func (c *Client) Request(request *http.Request) (*http.Response, error) {
	if !c.IsAuthenticated() {
		return nil, ErrNotAuthenticated
	}

	// Append DPoP token
	dpop, err := c.createDPoPToken(request)
	if err != nil {
		return nil, err
	}
	request.Header.Add("DPoP", dpop)

	return c.httpClient.Do(request)
}

// SetHTTPClient sets the HTTP client for internal use.
func (c *Client) SetHTTPClient(client *http.Client) {
	c.httpClient = client
}
