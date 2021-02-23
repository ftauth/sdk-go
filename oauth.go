package ftauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ftauth/ftauth/pkg/model"
	"golang.org/x/oauth2"
)

// AuthorizationCodeResponse holds the query parameters returned
// from a successful Authorize call, as well as an error if any
// error occurred.
type AuthorizationCodeResponse struct {
	Code  string
	State string
	Error error
}

func (authResp *AuthorizationCodeResponse) String() string {
	return fmt.Sprintf("{Code: %s, State: %s, Error: %v}", authResp.Code, authResp.State, authResp.Error)
}

type tokenRefresher struct {
	ctx          context.Context
	client       *Client
	refreshToken string
}

func (ref *tokenRefresher) Token() (*oauth2.Token, error) {
	if ref.refreshToken == "" {
		return nil, errors.New("token expired and refresh token is not set")
	}

	tokenEndpoint, err := url.Parse(ref.client.Config.GatewayURL)
	if err != nil {
		return nil, err
	}
	tokenEndpoint.Path = tokenEndpoint.Path + "/token"

	body := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {ref.refreshToken},
	}

	buf := strings.NewReader(body.Encode())
	resp, err := http.Post(tokenEndpoint.String(), "application/json", buf)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var response model.TokenResponse
		err = json.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			return nil, err
		}

		token := &oauth2.Token{
			AccessToken:  response.AccessToken,
			RefreshToken: response.RefreshToken,
			Expiry:       time.Unix(int64(response.ExpiresIn), 0),
		}

		ref.refreshToken = response.RefreshToken

		ref.saveNewToken(token)

		return token, nil
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("error refreshing: %d %s", resp.StatusCode, b)
}

func (ref *tokenRefresher) saveNewToken(token *oauth2.Token) error {
	// TODO: Make logger global lo("Saving access and refresh tokens...")
	err := ref.client.KeyStore.Save(KeyAccessToken, []byte(token.AccessToken))
	if err != nil {
		return err
	}

	err = ref.client.KeyStore.Save(KeyRefreshToken, []byte(token.RefreshToken))
	if err != nil {
		return err
	}

	return nil
}
