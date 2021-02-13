package ftauthinternal

import (
	"github.com/ftauth/ftauth/pkg/model"
	ftauth "github.com/ftauth/sdk-go"
)

// UserData holds the key user data for sharing externally.
type UserData model.UserData

// AuthorizationCodeResponse holds the query parameters returned
// from a successful Authorize call, as well as an error if any
// error occurred.
type AuthorizationCodeResponse ftauth.AuthorizationCodeResponse

// NewAuthorizationCodeResponse creates a new authorization code response with
// the query parameters of a successful callback.
func NewAuthorizationCodeResponse(code, state string, err error) *AuthorizationCodeResponse {
	return &AuthorizationCodeResponse{Code: code, State: state, Error: err}
}

// AuthorizationCodeCompleter handles client-side asynchronous
// completion of an authorization request.
type AuthorizationCodeCompleter interface {
	Complete(authResp *AuthorizationCodeResponse, err error)
}

// LoginCompleter can be used by the mobile side to receive
// a notification when the login process completed successfully
// (with a username), or with an error.
type LoginCompleter interface {
	Complete(user *UserData, err error)
}

// ErrorCompleter completes with an error (or nil).
type ErrorCompleter interface {
	Complete(err error)
}

// WebViewLauncher handles opening URLs on mobile/desktop clients.
type WebViewLauncher interface {
	LaunchURL(url string, completer AuthorizationCodeCompleter)
}
