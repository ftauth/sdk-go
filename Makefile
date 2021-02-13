OUTPUT := ../sdk-ios/FTAuthInternal.framework
CODECOV := coverage.txt

.PHONY: build
build: clean
	GOPRIVATE=github.com/ftauth gomobile bind -target ios -o $(OUTPUT) -v ./mobile


.PHONY: test
test:
	GOPRIVATE=github.com/ftauth CGO_ENABLED=0 go test -v -coverprofile=$(CODECOV) .

.PHONY: clean
clean:
	rm -rf $(OUTPUT)