BUILD_OUT=build

darwin-arm64:
	GOOS=darwin \
	GOARCH=arm64 \
	CGO_ENABLED=1 \
	CLANGARCH=arm64 \
	go build -buildmode=c-archive -o $(BUILD_OUT)/libpolygonid-darwin-arm64.a ./cmd/polygonid
