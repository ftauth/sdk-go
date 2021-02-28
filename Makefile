IOS_OUTPUT := ../sdk-ios/FTAuthInternal.framework
ANDROID_OUTPUT := ../sdk-android/ftauthinternal/ftauthinternal.aar
CODECOV := coverage.txt

.PHONY: ios
ios:
	gomobile bind -target ios -o $(IOS_OUTPUT) -v ./mobile

.PHONY: android
android:
	gomobile bind -target android -o $(ANDROID_OUTPUT) -v ./mobile

.PHONY: test
test:
	CGO_ENABLED=0 go test -v -coverprofile=$(CODECOV) ./...

.PHONY: clean
clean:
	rm -rf $(IOS_OUTPUT) $(ANDROID_OUTPUT)