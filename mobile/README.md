# FTAuth Mobile [![codecov](https://codecov.io/gh/ftauth/sdk-mobile/branch/main/graph/badge.svg?token=QGFUXZPAII)](https://codecov.io/gh/ftauth/sdk-mobile)
Mobile bindings for the FTAuth Go client, allowing cross-platform deployment to iOS and Android.

## Test
```
go test
```

## Build
### iOS
```
gomobile bind -target ios -o FTAuthInternal.framework
```