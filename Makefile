IOS_OUT=ios

ios-arm64:
	GOOS=ios \
	GOARCH=arm64 \
	CGO_ENABLED=1 \
	SDK=iphoneos \
	TARGET=arm64-apple-ios16 \
	CC=$(PWD)/clangwrap.sh \
	CGO_CFLAGS="-fembed-bitcode" \
	go build -buildmode=c-archive -o $(IOS_OUT)/libpolygonid-ios.a ./cmd/polygonid
	cp $(IOS_OUT)/libpolygonid-ios.h $(IOS_OUT)/libpolygonid.h


ios-simulator-x86_64:
	GOOS=darwin \
	GOARCH=amd64 \
	CGO_ENABLED=1 \
	SDK=iphonesimulator \
	TARGET=x86-64-apple-ios16-simulator \
	CC=$(PWD)/clangwrap.sh \
	CGO_CFLAGS="-fembed-bitcode" \
	go build -tags ios -buildmode=c-archive -o $(IOS_OUT)/libpolygonid-ios-simulator-x86_64.a ./cmd/polygonid
	cp $(IOS_OUT)/libpolygonid-ios-simulator-x86_64.h $(IOS_OUT)/libpolygonid.h

ios-simulator-arm64:
	GOOS=darwin \
	GOARCH=arm64 \
	CGO_ENABLED=1 \
	SDK=iphonesimulator \
	TARGET=arm64-apple-ios16-simulator \
	CC=$(PWD)/clangwrap.sh \
	CGO_CFLAGS="-fembed-bitcode" \
	go build -tags ios -buildmode=c-archive -o $(IOS_OUT)/libpolygonid-ios-simulator-arm64.a ./cmd/polygonid
	cp $(IOS_OUT)/libpolygonid-ios-simulator-arm64.h $(IOS_OUT)/libpolygonid.h

darwin-arm64:
	GOOS=darwin \
	GOARCH=arm64 \
	CGO_ENABLED=1 \
	go build -buildmode=c-archive -o $(IOS_OUT)/libpolygonid-darwin-arm64.a ./cmd/polygonid
	cp $(IOS_OUT)/libpolygonid-darwin-arm64.h $(IOS_OUT)/libpolygonid.h

# Build a legacy multi-architecture version of libpolygonid.a with iOS Device arm64 & iOS Simulator x86_64
ios-old: ios-arm64 ios-simulator-x86_64
	lipo $(IOS_OUT)/libpolygonid-ios.a $(IOS_OUT)/libpolygonid-ios-simulator-x86_64.a -create -output $(IOS_OUT)/libpolygonid.a
	cp $(IOS_OUT)/libpolygonid-ios.h $(IOS_OUT)/libpolygonid.h

ios-simulator: ios-simulator-x86_64 ios-simulator-arm64
	lipo $(IOS_OUT)/libpolygonid-ios-simulator-x86_64.a $(IOS_OUT)/libpolygonid-ios-simulator-arm64.a -create -output $(IOS_OUT)/libpolygonid-ios-simulator.a
	cp $(IOS_OUT)/libpolygonid-ios-simulator-arm64.h $(IOS_OUT)/libpolygonid.h

ios: ios-old ios-arm64 ios-simulator

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
