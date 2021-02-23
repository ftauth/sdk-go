package ftauthinternal

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/ftauth/ftauth/pkg/model"
	"github.com/ftauth/ftauth/pkg/oauth"
	ft "github.com/ftauth/sdk-go"
	"golang.org/x/oauth2"
)

// Common errors.
var (
	ErrInvalidState = errors.New("invalid state")

	log = ft.NullLogger
)

// KeyStore exchanges private key data with a backend keychain.
// Implementations will vary by client, but all should be encrypted
// or reasonably protected against attacks.
type KeyStore ft.KeyStore

// ErrUnknown creates an unknown error.
func ErrUnknown(details string) error {
	return &ft.KeyStoreError{Code: ft.KeyStoreErrorCodeUnknown, Details: details}
}

// ErrAccess creates an access error.
func ErrAccess(details string) error {
	return &ft.KeyStoreError{Code: ft.KeyStoreErrorCodeAccess, Details: details}
}

// ErrKeyNotFound creates a key not found error.
func ErrKeyNotFound(key string) error {
	return &ft.KeyStoreError{Code: ft.KeyStoreErrorCodeKey, Details: key}
}

// Logger lets the mobile platform define the logging interface.
type Logger ft.Logger

// Request holds an HTTP request.
type Request ft.Request

// Response holds an HTTP response.
type Response struct {
	Request    *Request
	StatusCode int
	Body       []byte
}

// Client communicates with HTTP services on behalf
// of an authenticated user.
type Client struct {
	*ft.Client
	errCh        chan error
	resCh        chan *AuthorizationCodeResponse
	state        string
	codeVerifier string
	webView      WebViewLauncher
}

// ClientConfig holds client options and settings.
type ClientConfig ft.ClientConfig

// NewClientConfig creates a new object holding all the information
// needed to initialize an FTAuth client.
func NewClientConfig(
	gatewayURL string,
	clientID string,
	clientSecret string,
	clientType string,
	redirectURI string,
	scope string,
	timeout int,
) (*ClientConfig, error) {
	config := &ft.ClientConfig{
		GatewayURL:   gatewayURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		ClientType:   model.ClientType(clientType),
		RedirectURI:  redirectURI,
		Scopes:       strings.Fields(scope),
		Timeout:      uint(timeout),
	}
	if err := config.Valid(); err != nil {
		return nil, err
	}
	return (*ClientConfig)(config), nil
}

// Config holds options for configuring the client.
// Use DefaultOptions if unsure.
type Config ft.Config

// GetClientConfig returns the configured client options.
func (config *Config) GetClientConfig() *ClientConfig {
	return (*ClientConfig)(config.ClientConfig)
}

func providerFromEnum(enum int) model.Provider {
	switch enum {
	case 0:
		return model.ProviderFTAuth
	case 1:
		return model.ProviderApple
	case 2:
		return model.ProviderGoogle
	case 3:
		return model.ProviderMicrosoft
	default:
		return ""
	}
}

// NewClient creates a new FTAuth client
func NewClient(config *Config) (*Client, error) {
	ftConfig := (*ft.Config)(config)

	if err := ftConfig.Valid(); err != nil {
		return nil, err
	}

	client, err := ft.NewClient(ftConfig)
	if err != nil {
		return nil, err
	}

	return &Client{
		Client: client,
		errCh:  make(chan error),
		resCh:  make(chan *AuthorizationCodeResponse),
	}, nil
}

// Complete handles completion of an authorization code request.
func (c *Client) Complete(authResp *AuthorizationCodeResponse, err error) {
	if err != nil {
		c.errCh <- err
		return
	}
	if authResp == nil {
		c.errCh <- errors.New("nil response")
		return
	}
	if authResp.State != c.state {
		c.errCh <- ErrInvalidState
		return
	}
	if authResp.Error != nil {
		c.errCh <- authResp.Error
		return
	}

	c.resCh <- authResp
}

// Authorize returns a URL through which the user must authenticate. The client is responsible for listening to redirect steps and
// capturing the query parameters for use with Exchange.
func (c *Client) Authorize(provider model.Provider) (string, error) {
	var err error
	c.state, err = generateState()
	if err != nil {
		return "", err
	}

	var codeChallenge string
	c.codeVerifier, codeChallenge = generateCodeChallenge()
	codeChallengeMethod := "S256"

	var opts []oauth2.AuthCodeOption
	codeChallengeOpt := oauth2.SetAuthURLParam("code_challenge", codeChallenge)
	codeChallengeMethodOpt := oauth2.SetAuthURLParam("code_challenge_method", codeChallengeMethod)
	opts = []oauth2.AuthCodeOption{codeChallengeOpt, codeChallengeMethodOpt}

	switch provider {
	case model.ProviderFTAuth:
		break
	default:
		providerOpt := oauth2.SetAuthURLParam("provider", string(provider))
		opts = append(opts, providerOpt)
	}

	url := c.OauthConfig.AuthCodeURL(c.state, opts...)
	return url, nil
}

type exchangeRoundTripper struct {
	clientID string
}

func (rt *exchangeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		defer func() {
			req.Body.Close()
		}()
	}

	req2 := cloneRequest(req)

	basicAuth := oauth.CreateBasicAuthorization(rt.clientID, "")
	req2.Header.Add("Authorization", basicAuth)

	return http.DefaultTransport.RoundTrip(req2)
}

// cloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	return r2
}

func newExchangeRoundTripper(clientID string) *exchangeRoundTripper {
	return &exchangeRoundTripper{clientID}
}

// Exchange communicates with the FTAuth server, exchanging the authorization code for an access + refresh token.
func (c *Client) Exchange(authResp *AuthorizationCodeResponse) (*http.Client, error) {
	baseClient := &http.Client{
		Timeout:   time.Duration(c.Config.Timeout) * time.Second,
		Transport: newExchangeRoundTripper(c.Config.ClientID),
	}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, baseClient)

	codeVerifierOpt := oauth2.SetAuthURLParam("code_verifier", c.codeVerifier)
	token, err := c.OauthConfig.Exchange(ctx, authResp.Code, codeVerifierOpt)
	if err != nil {
		return nil, err
	}

	log.Debugln("Received access token: ", token.AccessToken)
	log.Debugln("Received refresh token: ", token.RefreshToken)

	// Save tokens to Keychain
	c.SaveTokens(token.AccessToken, token.RefreshToken)

	return oauth2.NewClient(ctx, ft.TokenSource(token)), nil
}

// Login triggers the authentication flow and handles redirects
// on the mobile side to return an authenticated HTTP client.
func (c *Client) Login(provider int, webView WebViewLauncher, completion LoginCompleter) {
	log.Debugln("Client initiated login flow")

	// Since phone UI must run on the main thread, which we are currently
	// also on, do not block with receiving channels in Authorize. Instead, spin
	// up a goroutine and have the mobile side explicitly run UI-code on main thread.
	// This effectively opens up the main thread exclusively for UI work on the phone.
	//
	// time 		Main Thread				  Authorize Thread						QOS Thread
	//	 1		 go func Authorize
	//	 2							  			<-Authorize
	//	 3			    												DispatchQueue.main.async { showUI() }
	//	 4				UI
	//	 5			 User Login					 							Completer.complete(code, state)
	//   6										  Exchange
	//   7 			 closeUI()
	//   8				Done

	url, err := c.Authorize(providerFromEnum(provider))
	if err != nil {
		completion.Complete(nil, err)
		return
	}

	go func() {
		log.Infoln("Launching URL: ", url)
		webView.LaunchURL(url, c)
		log.Infoln("Waiting for client response...")
	}()

	for {
		select {
		case err := <-c.errCh:
			log.Errorln("Error launching URL: ", err)
			completion.Complete(nil, err)
			return
		case authResp := <-c.resCh:
			log.Debugln("Recevied authorization response: ", authResp)
			client, err := c.Exchange(authResp)
			if err != nil {
				completion.Complete(nil, err)
				return
			}
			c.SetHTTPClient(client)

			user, err := c.CurrentUser()
			if err != nil {
				completion.Complete(nil, err)
				return
			}

			log.Infoln("Logged in with user: ", user)

			completion.Complete((*UserData)(user), nil)
			return
		case <-time.After(5 * time.Second):
			log.Debugln("Waiting for client response...")
		}
	}
}

// SignInWithApple is a special login function for working with Apple's login system on iOS 13.
// iOS 12 and all other providers use the Login function with the provider specified.
func (c *Client) SignInWithApple(user *SignInWithAppleData) (*UserData, error) {
	switch user.CredentialType {
	case AppleCredentialTypeAppleID:
		// In this case, Apple holds all the information and controls its own access/refresh tokens.
		// We still need to issue FTAuth access/refresh tokens, so we create a new user in the database
		// and log them in using the identity token.

	case AppleCredentialTypePassword:
		// In this case we must use ROPC to login the user.

	}
	return nil, nil
}

func setupLogger(logger Logger) {
	log = &ft.LoggerImpl{Logger: logger}
}

// NewConfigWithJSON creates an options object for configuring
// an FTAuth client with client config in JSON format.
func NewConfigWithJSON(
	keyStore KeyStore,
	logger Logger,
	clientConfigJSON []byte,
) (*Config, error) {
	var clientConfig ft.ClientConfig
	if err := json.Unmarshal(clientConfigJSON, &clientConfig); err != nil {
		return nil, err
	}
	return NewConfig(keyStore, logger, (*ClientConfig)(&clientConfig))
}

// NewConfig creates an options object for configuring
// an FTAuth client.
func NewConfig(
	keyStore KeyStore,
	logger Logger,
	clientConfig *ClientConfig,
) (*Config, error) {
	if err := (*ft.ClientConfig)(clientConfig).Valid(); err != nil {
		return nil, err
	}

	setupLogger(logger)

	return &Config{
		KeyStore:     keyStore,
		ClientConfig: (*ft.ClientConfig)(clientConfig),
		Logger:       &ft.LoggerImpl{Logger: logger},
	}, nil
}

// NewRequest creates a new HTTP request
func NewRequest(method, uri string, body []byte) *Request {
	return &Request{Method: method, URL: uri, Body: body}
}

// Request performs an HTTP request on behalf of an authenticated user.
func (c *Client) Request(request *Request) (*Response, error) {
	if request == nil {
		return nil, errors.New("empty request")
	}
	resp, err := c.Client.Request((*ft.Request)(request))
	if err != nil {
		log.Errorln("Error in HTTP request: ", err)
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorln("Error reading HTTP response: ", err)
		return nil, err
	}

	return &Response{
		Request:    request,
		StatusCode: resp.StatusCode,
		Body:       respBody,
	}, nil
}
