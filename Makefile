IOS_OUT=ios

ios-arm64:
	GOOS=ios \
	GOARCH=arm64 \
	CGO_ENABLED=1 \
	CLANGARCH=arm64 \
	SDK=iphoneos16.1 \
	CC=$(PWD)/clangwrap.sh \
	CGO_CFLAGS="-fembed-bitcode" \
	go build -buildmode=c-archive -o $(IOS_OUT)/libpolygonid-ios.a ./cmd/polygonid


ios-simulator:
	GOOS=darwin \
	GOARCH=amd64 \
	CGO_ENABLED=1 \
	CLANGARCH=x86_64 \
	SDK=iphonesimulator16.1 \
	CC=$(PWD)/clangwrap.sh \
	CGO_CFLAGS="-fembed-bitcode" \
	go build -buildmode=c-archive -o $(IOS_OUT)/libpolygonid-ios-simulator.a ./cmd/polygonid

darwin-arm64:
	GOOS=darwin \
	GOARCH=arm64 \
	CGO_ENABLED=1 \
	CLANGARCH=arm64 \
	go build -buildmode=c-archive -o $(IOS_OUT)/libpolygonid-darwin-arm64.a ./cmd/polygonid

ios: ios-arm64 ios-simulator
	lipo $(IOS_OUT)/libpolygonid-ios.a $(IOS_OUT)/libpolygonid-ios-simulator.a -create -output $(IOS_OUT)/libpolygonid.a
	cp $(IOS_OUT)/libpolygonid-ios.h $(IOS_OUT)/libpolygonid.h

dylib:
	go build -buildmode=c-shared -o $(IOS_OUT)/libpolygonid.dylib ./cmd/polygonid