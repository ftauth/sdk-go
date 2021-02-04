package ftauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"path"
	"time"

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
	tokenEndpoint.Path = path.Join(tokenEndpoint.Path, "token")

	body := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {ref.refreshToken},
	}

	buf := bytes.NewBuffer([]byte(body.Encode()))
	resp, err := http.Post(tokenEndpoint.String(), "application/json", buf)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var response struct {
			AccessToken  string `json:"access_token"`
			TokenType    string `json:"token_type"`
			RefreshToken string `json:"refresh_token"`
			ExpiresIn    int    `json:"expires_in"`
		}
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
	log.Println("Saving access and refresh tokens...")
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
