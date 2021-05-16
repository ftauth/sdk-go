package ftauthinternal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/ftauth/ftauth/pkg/model"
	ftauth "github.com/ftauth/sdk-go"
	"github.com/stretchr/testify/require"
)

var mockClientConfig *ftauth.ClientConfig

func init() {
	serverHost := os.Getenv("FTAUTH_SERVER_HOST")
	if serverHost == "" {
		serverHost = "localhost"
	}
	serverPort := os.Getenv("FTAUTH_SERVER_PORT")
	if serverPort == "" {
		serverPort = "8000"
	}
	serverAddr := fmt.Sprintf("http://%s:%s", serverHost, serverPort)
	adminID := os.Getenv("FTAUTH_OAUTH_ADMIN_CLIENTID")
	if adminID == "" {
		adminID = "3cf9a7ac-9198-469e-92a7-cc2f15d8b87d"
	}
	mockClientConfig = &ftauth.ClientConfig{
		GatewayURL:  serverAddr,
		ClientID:    adminID,
		ClientType:  model.ClientTypePublic,
		RedirectURI: "http://localhost:8081/redirect",
		Scopes:      []string{"admin", "default"},
		Timeout:     30,
	}
}

func newRedirectServer(f http.HandlerFunc) *http.Server {
	r := http.NewServeMux()
	r.HandleFunc("/redirect", f)

	srv := &http.Server{
		Addr:    ":8081",
		Handler: r,
	}

	return srv
}

type mockKeyStore struct {
	store map[string]string
}

func newMockKeyStore() *mockKeyStore {
	return &mockKeyStore{make(map[string]string)}
}

func (ks *mockKeyStore) Save(key string, value []byte) error {
	ks.store[key] = string(value)
	return nil
}

func (ks *mockKeyStore) Get(key string) ([]byte, error) {
	if value, ok := ks.store[key]; ok {
		return []byte(value), nil
	}
	return nil, ErrKeyNotFound(key)
}

func (ks *mockKeyStore) Clear() error {
	ks.store = map[string]string{}
	return nil
}

func (ks *mockKeyStore) Delete(key string) error {
	delete(ks.store, key)
	return nil
}

type mockWebView struct {
	client *Client
}

func (webView *mockWebView) LaunchURL(url string, completer AuthorizationCodeCompleter) {
	// No-Headless opts
	// opts := append(chromedp.DefaultExecAllocatorOptions[:2], chromedp.DefaultExecAllocatorOptions[3:]...)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background())
	defer cancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	fmt.Println("Loading url: ", url)

	var code string
	var state string
	var err string
	var errDesc string
	ch := make(chan struct{})
	srv := newRedirectServer(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		code = query.Get("code")
		state = query.Get("state")
		err = query.Get("error")
		errDesc = query.Get("error_description")
		cancel()
		close(ch)
	})

	go srv.ListenAndServe()

	usernameSelector := `#username`
	passwordSelector := `#password`
	submitSelector := `#submit`
	chromeErr := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.WaitVisible(usernameSelector),
		chromedp.SendKeys(usernameSelector, "admin"),
		chromedp.WaitVisible(passwordSelector),
		chromedp.SendKeys(passwordSelector, "password"),
		chromedp.Click(submitSelector),
		chromedp.ActionFunc(func(c context.Context) error {
			ch := chromedp.WaitNewTarget(ctx, func(info *target.Info) bool {
				return strings.HasPrefix(info.URL, "http://localhost:8081")
			})

			select {
			case <-ch:
				return nil
			case <-time.After(3 * time.Second):
				return errors.New("timeout")
			}
		}),
	)
	if ctx.Err() != nil {
		// Ignore if we canceled context
	} else {
		webView.client.errCh <- chromeErr
		return
	}

	<-ch

	srv.Close()

	if code != "" && state != "" {
		go completer.Complete(&AuthorizationCodeResponse{Code: code, State: state}, nil)
	} else {
		go completer.Complete(&AuthorizationCodeResponse{State: state, Error: fmt.Errorf("%s: %s", err, errDesc)}, nil)
	}
}

func TestRequest(t *testing.T) {
	client, err := NewClient(&Config{
		KeyStore:     newMockKeyStore(),
		ClientConfig: mockClientConfig,
		Logger:       ftauth.StdLogger,
	})
	require.NoError(t, err)

	// Make an authenticated request
	request := NewRequest(http.MethodGet, "http://localhost:8000/user", nil)
	_, err = client.Request(request)
	require.EqualError(t, err, ftauth.ErrNotAuthenticated.Error())
}

type mockLoginCompletion struct {
	t *testing.T
}

func (completion *mockLoginCompletion) Complete(user *UserData, err error) {
	require.NoError(completion.t, err)
}

func TestLogin(t *testing.T) {
	client, err := NewClient(&Config{
		KeyStore:     newMockKeyStore(),
		ClientConfig: mockClientConfig,
		Logger:       ftauth.StdLogger,
	})
	require.NoError(t, err)

	webViewLauncher := &mockWebView{client}
	client.Login(0, webViewLauncher, &mockLoginCompletion{t})
}
