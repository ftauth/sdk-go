module github.com/ftauth/sdk-go

go 1.15

replace (
	filippo.io/age => github.com/FiloSottile/age v1.0.0-beta6
	github.com/ftauth/ftauth => ../server
)

require (
	filippo.io/age v1.0.0-beta6
	github.com/chromedp/cdproto v0.0.0-20210204225631-566b5dbfe5c0
	github.com/chromedp/chromedp v0.6.5
	github.com/ftauth/ftauth v0.0.0-20210130010958-5eba580f74c7
	github.com/golang/protobuf v1.4.3 // indirect
	github.com/google/go-cmp v0.5.4 // indirect
	github.com/google/uuid v1.2.0
	github.com/mitchellh/mapstructure v1.4.1 // indirect
	github.com/stretchr/testify v1.5.1
	golang.org/x/net v0.0.0-20210119194325-5f4716e94777 // indirect
	golang.org/x/oauth2 v0.0.0-20210126194326-f9ce19ea3013
	golang.org/x/sys v0.0.0-20210124154548-22da62e12c0c // indirect
	google.golang.org/appengine v1.6.7 // indirect
)
