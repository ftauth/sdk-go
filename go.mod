module github.com/ftauth/sdk-go

go 1.15

replace filippo.io/age => github.com/FiloSottile/age v1.0.0-rc.3

// replace github.com/ftauth/ftauth => ../server

require (
	filippo.io/age v1.0.0-rc.3
	github.com/chromedp/cdproto v0.0.0-20210728214956-1fab41c4e0b7
	github.com/chromedp/chromedp v0.7.4
	github.com/ftauth/ftauth v0.0.0-20210730232401-e2d7e9e8e8d1
	github.com/stretchr/testify v1.7.0
	golang.org/x/oauth2 v0.0.0-20210628180205-a41e5a781914
)
