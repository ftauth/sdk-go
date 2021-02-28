module github.com/ftauth/sdk-go

go 1.15

replace filippo.io/age => github.com/FiloSottile/age v1.0.0-beta6

// replace github.com/ftauth/ftauth => ../server

require (
	filippo.io/age v1.0.0-beta7
	github.com/chromedp/cdproto v0.0.0-20210227213635-aabfe75e3e09
	github.com/chromedp/chromedp v0.6.6
	github.com/ftauth/ftauth v0.0.0-20210228205509-ba672ed99522
	github.com/google/go-cmp v0.5.4 // indirect
	github.com/mitchellh/mapstructure v1.4.1 // indirect
	github.com/stretchr/testify v1.7.0
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83 // indirect
	golang.org/x/oauth2 v0.0.0-20210220000619-9bb904979d93
	golang.org/x/sys v0.0.0-20210228012217-479acdf4ea46 // indirect
	google.golang.org/appengine v1.6.7 // indirect
)
