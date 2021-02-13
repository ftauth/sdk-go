package ftauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path"
	"sync"
	"time"

	"filippo.io/age"
	"github.com/ftauth/ftauth/pkg/jwt"
	"github.com/ftauth/ftauth/pkg/model"
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
	KeyAccessToken   = []byte("access_token")
	KeyRefreshToken  = []byte("refresh_token")
	keySigningKey    = []byte("signing_key")
	keyEncryptionKey = []byte("encryption_key")
)

// Client communicates with HTTP services on behalf
// of an authenticated user.
type Client struct {
	accessToken   *jwt.Token
	refreshToken  *jwt.Token
	signingKey    *jwt.Key
	encryptionKey *age.X25519Identity
	Config        *ClientConfig
	KeyStore      KeyStore
	OauthConfig   *model.OAuthConfig
	*LoggerImpl

	sync.RWMutex // protects httpClient
	httpClient   *http.Client
}

// Config holds options for configuring the client.
// Use DefaultOptions if unsure.
type Config struct {
	KeyStore     KeyStore
	Logger       *LoggerImpl
	ClientConfig *ClientConfig
}

// NewClient creates a new FTAuth client with the given options.
// Use DefaultOptions if unsure.
func NewClient(config *Config) (*Client, error) {
	if config.KeyStore == nil {
		return nil, ErrInvalidKeyStore
	}
	if config.Logger == nil || config.Logger.Logger == nil {
		config.Logger = NullLogger
	}

	gatewayURL, err := url.Parse(config.ClientConfig.GatewayURL)
	if err != nil {
		return nil, err
	}
	authURL := *gatewayURL
	authURL.Path = path.Join(gatewayURL.Path, "authorize")

	tokenURL := *gatewayURL
	tokenURL.Path = path.Join(gatewayURL.Path, "token")

	jwksURL := *gatewayURL
	jwksURL.Path = path.Join(gatewayURL.Path, "jwks.json")

	c := &Client{
		KeyStore:   config.KeyStore,
		Config:     config.ClientConfig,
		LoggerImpl: config.Logger,

		// Default provider is FTAuth
		OauthConfig: &model.OAuthConfig{
			Provider: model.ProviderFTAuth,
			Config: &oauth2.Config{
				ClientID: config.ClientConfig.ClientID,
				Endpoint: oauth2.Endpoint{
					AuthURL:  authURL.String(),
					TokenURL: tokenURL.String(),
				},
				RedirectURL: config.ClientConfig.RedirectURI,
				Scopes:      config.ClientConfig.Scopes,
			},
			JWKSetURL: jwksURL.String(),
		},
	}

	err = c.Initialize()
	if err != nil {
		c.Errorln("Error initializing client: ", err)
		return nil, err
	}

	return c, nil
}

// Configure initializes OAuth information for the FTAuth client.
// Depending on the provider, for example, it will change how we
// initialize it.
func (c *Client) Configure(oauthConfig *model.OAuthConfig) {
	c.OauthConfig = oauthConfig
}

// CurrentUser returns the currently logged in user, if authenticated.
func (c *Client) CurrentUser() (*model.UserData, error) {
	if !c.IsAuthenticated() {
		return nil, ErrNotAuthenticated
	}
	customClaims := c.accessToken.Claims.CustomClaims
	if customClaims == nil {
		return nil, jwt.ErrInvalidPayloadFormat
	}
	userInfo, ok := customClaims["userInfo"]
	if !ok {
		return nil, jwt.ErrInvalidPayloadFormat
	}
	user, ok := userInfo.(map[string]interface{})
	if !ok {
		return nil, jwt.ErrInvalidPayloadFormat
	}
	data, err := json.Marshal(user)
	if err != nil {
		return nil, jwt.ErrInvalidPayloadFormat
	}

	var userData model.UserData
	err = json.Unmarshal(data, &userData)
	if err != nil {
		return nil, jwt.ErrInvalidPayloadFormat
	}

	return &userData, nil
}

// SaveTokens validates and stores the tokens in the Keystore.
func (c *Client) SaveTokens(accessTokenJWT, refreshTokenJWT string) error {
	// TODO: Validate tokens against server public key

	var err error
	c.accessToken, err = jwt.Decode(accessTokenJWT)
	if err != nil {
		return err
	}
	c.refreshToken, err = jwt.Decode(refreshTokenJWT)
	if err != nil {
		return err
	}

	err = c.KeyStore.Save(KeyAccessToken, []byte(accessTokenJWT))
	if err != nil {
		return err
	}
	err = c.KeyStore.Save(KeyRefreshToken, []byte(refreshTokenJWT))
	if err != nil {
		return err
	}

	return nil
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

	c.Debugln("Loading access token...")
	accessJWT, err := c.KeyStore.Get(KeyAccessToken)
	if err != nil && !isErrKeyNotFound(err) {
		c.Errorln("Error loading access token: ", err)
		return err
	}
	if accessJWT != nil {
		c.Debugln("Access token found")
		accessToken, err := jwt.Decode(string(accessJWT))
		if err != nil {
			return err
		}
		if !accessToken.IsExpired() {
			c.accessToken = accessToken
			validAccessToken = true
		}
	} else {
		c.Debugln("Access token not found")
	}

	if validAccessToken {
		var validRefreshToken bool
		c.Debugln("Loading refresh token...")
		refreshJWT, err := c.KeyStore.Get(KeyRefreshToken)
		if err != nil && !isErrKeyNotFound(err) {
			c.Errorln("Error loading refresh token: ", err)
			return err
		}
		if refreshJWT != nil {
			c.Debugln("Refresh token found")
			refreshToken, err := jwt.Decode(string(refreshJWT))
			if err != nil {
				return err
			}
			if !refreshToken.IsExpired() {
				c.refreshToken = refreshToken
				validRefreshToken = true
			}
		} else {
			c.Debugln("Refresh token not found")
		}

		if validRefreshToken {
			c.Debugln("Validated tokens. Reloading HTTP client...")
			token := &oauth2.Token{
				AccessToken:  string(accessJWT),
				RefreshToken: string(refreshJWT),
				Expiry:       time.Unix(c.accessToken.Claims.ExpirationTime, 0),
			}
			c.httpClient = oauth2.NewClient(context.Background(), TokenSource(token))
		}
	}

	c.Debugln("Loading signing key...")
	privateJWK, err := c.KeyStore.Get(keySigningKey)
	if err != nil && !isErrKeyNotFound(err) {
		c.Errorln("Error loading signing key: ", err)
		return err
	}
	if privateJWK != nil {
		c.Debugln("Signing key found")
		c.signingKey, err = jwt.ParseJWK(string(privateJWK))
		if err != nil {
			return err
		}
	} else {
		c.Debugln("Signing key not found")
		c.Debugln("Generating signing key...")
		privateKey, err := generatePrivateSigningKey()
		if err != nil {
			return err
		}
		c.signingKey, err = jwt.NewJWKFromRSAPrivateKey(privateKey)
		if err != nil {
			return err
		}
		b, err := json.Marshal(c.signingKey)
		if err != nil {
			return err
		}
		err = c.KeyStore.Save(keySigningKey, b)
		if err != nil {
			return err
		}
	}

	c.Debugln("Loading encryption key...")
	privateEncryptionKey, err := c.KeyStore.Get(keyEncryptionKey)
	if err != nil && !isErrKeyNotFound(err) {
		c.Errorln("Error loading encryption key: ", err)
		return err
	}
	if privateEncryptionKey != nil {
		c.Debugln("Encryption key found")
		c.encryptionKey, err = age.ParseX25519Identity(string(privateEncryptionKey))
		if err != nil {
			return err
		}
	} else {
		c.Debugln("Encryption key not found")
		c.Debugln("Generating encryption key...")
		c.encryptionKey, err = age.GenerateX25519Identity()
		if err != nil {
			return err
		}
		err = c.KeyStore.Save(keyEncryptionKey, []byte(c.encryptionKey.String()))
		if err != nil {
			return err
		}
	}

	c.Infoln("Client successfully loaded")

	return nil
}

func generatePrivateSigningKey() (*rsa.PrivateKey, error) {
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

// TokenSource provides a refreshing token source linked to the KeyStore
// which is compatible with the oauth2 library.
func TokenSource(token *oauth2.Token) oauth2.TokenSource {
	return oauth2.ReuseTokenSource(token, &tokenRefresher{
		ctx:          context.Background(),
		refreshToken: token.RefreshToken,
	})
}

// IsAuthenticated returns true if the user has an authenticated HTTP client.
func (c *Client) IsAuthenticated() bool {
	if c.accessToken == nil {
		return false
	}
	return true
}

// Request performs an HTTP request on behalf of the authenticated user,
// automatically refreshing credentials as needed.
func (c *Client) Request(request *Request) (*http.Response, error) {
	if !request.Public && !c.IsAuthenticated() {
		return nil, ErrNotAuthenticated
	}

	var req *http.Request
	var err error
	if request.Body != nil {
		body := bytes.NewBuffer(request.Body)
		req, err = http.NewRequest(request.Method, request.URL, body)
	} else {
		req, err = http.NewRequest(request.Method, request.URL, nil)
	}
	if err != nil {
		return nil, err
	}

	// Append DPoP token
	dpop, err := c.createDPoPToken(req)
	if err != nil {
		return nil, err
	}
	req.Header.Add("DPoP", dpop)

	c.Lock()
	defer c.Unlock()
	return c.httpClient.Do(req)
}

// SetHTTPClient sets the HTTP client for internal use.
func (c *Client) SetHTTPClient(client *http.Client) {
	c.RLock()
	defer c.RUnlock()
	c.httpClient = client
}
