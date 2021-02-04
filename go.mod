module github.com/ftauth/sdk-go

go 1.15

replace (
	filippo.io/age => github.com/FiloSottile/age v1.0.0-beta6
	github.com/ftauth/ftauth => ../server
)

require (
	filippo.io/age v1.0.0-beta6
	github.com/ftauth/ftauth v0.0.0-20210130010958-5eba580f74c7
	github.com/golang/protobuf v1.4.3 // indirect
	github.com/google/uuid v1.2.0
	github.com/mitchellh/mapstructure v1.4.1 // indirect
	golang.org/x/net v0.0.0-20210119194325-5f4716e94777 // indirect
	golang.org/x/oauth2 v0.0.0-20210126194326-f9ce19ea3013
	google.golang.org/appengine v1.6.7 // indirect
)
