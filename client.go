package ftauth

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ftauth/ftauth/pkg/jwt"
)

// Common errors.
var (
	ErrNotAuthenticated = errors.New("the client is not authenticated")
	ErrNoRefreshToken   = errors.New("no refresh token")
)

// Common keys.
var (
	keyAccessToken  = []byte("ftauth.access_token")
	keyRefreshToken = []byte("ftauth.refresh_token")
	keyPrivateKey   = []byte("ftauth.private_key")
)

// Client communicates with HTTP services on behalf
// of an authenticated user.
type Client struct {
	accessToken  *jwt.Token
	refreshToken *jwt.Token
	privateKey   *jwt.Key
	client       *http.Client
	keyStore     KeyStore
	Options      ClientOptions
}

// ClientOptions holds options for configuring the client.
// Use DefaultOptions if unsure.
type ClientOptions struct {
	Timeout time.Duration
	UseDPoP bool
}

var (
	// DefaultOptions has sane defaults for configuring the FTAuth client.
	DefaultOptions = ClientOptions{
		Timeout: 60 * time.Second,
		UseDPoP: true,
	}
)

// NewClient creates a new FTAuth client with the given options.
// Use DefaultOptions if unsure.
func NewClient(keyStore KeyStore, opts ClientOptions) (*Client, error) {
	c := &Client{
		client: &http.Client{
			Timeout: opts.Timeout,
		},
		Options:  opts,
		keyStore: keyStore,
	}
	err := c.LoadFromKeyStore()
	if err != nil {
		return nil, err
	}

	return c, nil
}

// LoadFromKeyStore initializes the client with values from the KeyStore.
func (c *Client) LoadFromKeyStore() error {
	accessJWT, keyStoreErr := c.keyStore.Get(keyAccessToken)
	if keyStoreErr != nil && keyStoreErr.Code != KeyStoreErrorCodeKey {
		return keyStoreErr
	}
	if accessJWT != nil {
		var err error
		c.accessToken, err = jwt.Decode(string(accessJWT))
		if err != nil {
			return err
		}
	}

	refreshJWT, keyStoreErr := c.keyStore.Get(keyRefreshToken)
	if keyStoreErr != nil && keyStoreErr.Code != KeyStoreErrorCodeKey {
		return keyStoreErr
	}
	if refreshJWT != nil {
		var err error
		c.refreshToken, err = jwt.Decode(string(refreshJWT))
		if err != nil {
			return err
		}
	}

	privateJWK, keyStoreErr := c.keyStore.Get(keyPrivateKey)
	if keyStoreErr != nil && keyStoreErr.Code != KeyStoreErrorCodeKey {
		return keyStoreErr
	}
	if privateJWK != nil {
		var err error
		c.privateKey, err = jwt.ParseJWK(string(privateJWK))
		if err != nil {
			return err
		}
	}

	return nil
}

// Request performs an HTTP request on behalf of the authenticated user,
// automatically refreshing credentials as needed.
func (c *Client) Request(request *http.Request) (*http.Response, error) {
	if c.accessToken == nil {
		return nil, ErrNotAuthenticated
	}

	// Pre-check
	exp := c.accessToken.Claims.ExpirationTime
	if exp > 0 && time.Unix(exp, 0).Before(time.Now()) {
		err := c.refresh()
		if err != nil {
			return nil, err
		}
	}

	// Append access token
	bearer, err := c.accessToken.Raw()
	if err != nil {
		return nil, err
	}
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", bearer))

	// Append DPoP token, if being used
	if c.Options.UseDPoP {
		dpop, err := c.createDPoPToken(request)
		if err != nil {
			return nil, err
		}
		request.Header.Add("DPoP", dpop)
	}

	type httpResponse struct {
		resp *http.Response
		err  error
	}
	res := make(chan httpResponse)
	go func(result chan<- httpResponse) {
		var retries int
		var resp *http.Response
		var err error
		for {
			if retries == 3 {
				break
			}

			resp, err = c.client.Do(request)
			if err != nil {
				goto retry
			}

			if resp.StatusCode == http.StatusUnauthorized {
				resp = nil
				err = c.refresh()
				if err != nil {
					goto retry
				}
			}
		retry:
			retries++
			time.Sleep(500 * time.Millisecond)
		}

		result <- httpResponse{resp: resp, err: err}
	}(res)

	result := <-res
	return result.resp, result.err
}

// refresh performs a token refresh via the FTAuth server.
func (c *Client) refresh() error {
	if c.refreshToken == nil {
		return ErrNoRefreshToken
	}

	return nil
}
