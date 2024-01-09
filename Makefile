IOS_OUT=ios

ios-arm64:
	GOARCH=arm64 \
	SDK=iphoneos \
	MIN_VERSION=16 \
	./build-ios.sh

ios-sim-arm64:
	GOARCH=arm64 \
	SDK=iphonesimulator \
	MIN_VERSION=16 \
	./build-ios.sh

ios-sim-amd64:
	GOARCH=amd64 \
	SDK=iphonesimulator \
	MIN_VERSION=16 \
	./build-ios.sh

darwin-arm64:
	GOOS=darwin \
	GOARCH=arm64 \
	CGO_ENABLED=1 \
	CLANGARCH=arm64 \
	go build -buildmode=c-archive -o $(IOS_OUT)/libpolygonid-darwin-arm64.a ./cmd/polygonid

darwin-amd64:
	GOOS=darwin \
	GOARCH=amd64 \
	CGO_ENABLED=1 \
	CLANGARCH=x86_64 \
	go build -buildmode=c-archive -o $(IOS_OUT)/libpolygonid-darwin-amd64.a ./cmd/polygonid

ios-device: ios-arm64
	cp $(IOS_OUT)/libpolygonid-ios-arm64.a $(IOS_OUT)/libpolygonid-ios.a
	cp $(IOS_OUT)/libpolygonid-ios-arm64.h $(IOS_OUT)/libpolygonid.h

ios-simulator: ios-sim-arm64 ios-sim-amd64
	lipo $(IOS_OUT)/libpolygonid-ios-sim-amd64.a $(IOS_OUT)/libpolygonid-ios-sim-arm64.a -create -output $(IOS_OUT)/libpolygonid-ios-sim.a
	cp $(IOS_OUT)/libpolygonid-ios-sim-arm64.h $(IOS_OUT)/libpolygonid.h

ios: ios-device ios-simulator

darwin: darwin-arm64 darwin-amd64
	lipo $(IOS_OUT)/libpolygonid-darwin-arm64.a $(IOS_OUT)/libpolygonid-darwin-amd64.a -create -output $(IOS_OUT)/libpolygonid-darwin.a
	cp $(IOS_OUT)/libpolygonid-darwin-arm64.h $(IOS_OUT)/libpolygonid.h

dylib:
	go build -buildmode=c-shared -o $(IOS_OUT)/libpolygonid.dylib ./cmd/polygonid

ANDROID_OUT=android
ANDROID_NDK_HOME?=$(ANDROID_HOME)/ndk/22.1.7171670

android-armeabi-v7a:
	GOOS=android \
	GOARCH=arm \
	CGO_ENABLED=1 \
	CC=$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7a-linux-androideabi21-clang \
	go build -buildmode=c-shared -o $(ANDROID_OUT)/jnilibs/armeabi-v7a/libpolygonid.so ./cmd/polygonid

android-arm64-v8a:
	GOOS=android \
	GOARCH=arm64 \
	CGO_ENABLED=1 \
	CC=$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android21-clang \
	go build -buildmode=c-shared -o $(ANDROID_OUT)/jnilibs/arm64-v8a/libpolygonid.so ./cmd/polygonid

android-x86:
	GOOS=android \
	GOARCH=386 \
	CGO_ENABLED=1 \
	CC=$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/darwin-x86_64/bin/i686-linux-android21-clang \
	go build -buildmode=c-shared -o $(ANDROID_OUT)/jnilibs/x86/libpolygonid.so ./cmd/polygonid

android-x86-64:
	GOOS=android \
	GOARCH=amd64 \
	CGO_ENABLED=1 \
	CC=$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/darwin-x86_64/bin/x86_64-linux-android21-clang \
	go build -buildmode=c-shared -o $(ANDROID_OUT)/jnilibs/x86-64/libpolygonid.so ./cmd/polygonid

android: android-armeabi-v7a android-arm64-v8a android-x86 android-x86-64

all: android ios
