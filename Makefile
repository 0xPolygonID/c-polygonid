IOS_OUT=ios

ios-arm64:
	GOOS=ios \
	GOARCH=arm64 \
	CGO_ENABLED=1 \
	SDK=iphoneos \
	TARGET=arm64-apple-ios16 \
	CC=$(PWD)/clangwrap.sh \
	CGO_CFLAGS="-fembed-bitcode" \
	go build -tags prover_disabled -buildmode=c-archive -o $(IOS_OUT)/libpolygonid-ios.a ./cmd/polygonid
	cp $(IOS_OUT)/libpolygonid-ios.h $(IOS_OUT)/libpolygonid.h


ios-simulator-x86_64:
	GOOS=ios \
	GOARCH=amd64 \
	CGO_ENABLED=1 \
	SDK=iphonesimulator \
	TARGET=x86-64-apple-ios16-simulator \
	CC=$(PWD)/clangwrap.sh \
	CGO_CFLAGS="-fembed-bitcode -target x86_64-apple-ios16-simulator" \
	go build -tags ios,prover_disabled -buildmode=c-archive -o $(IOS_OUT)/libpolygonid-ios-simulator-x86_64.a ./cmd/polygonid
	cp $(IOS_OUT)/libpolygonid-ios-simulator-x86_64.h $(IOS_OUT)/libpolygonid.h

ios-simulator-arm64:
	GOOS=ios \
	GOARCH=arm64 \
	CGO_ENABLED=1 \
	SDK=iphonesimulator \
	TARGET=arm64-apple-ios16-simulator \
	CC=$(PWD)/clangwrap.sh \
	CGO_CFLAGS="-fembed-bitcode -target arm64-apple-ios16-simulator" \
	go build -tags ios,prover_disabled -buildmode=c-archive -o $(IOS_OUT)/libpolygonid-ios-simulator-arm64.a ./cmd/polygonid
	cp $(IOS_OUT)/libpolygonid-ios-simulator-arm64.h $(IOS_OUT)/libpolygonid.h

darwin-arm64:
	GOOS=darwin \
	GOARCH=arm64 \
	CGO_ENABLED=1 \
	go build -tags prover_disabled -buildmode=c-archive -o $(IOS_OUT)/libpolygonid-darwin-arm64.a ./cmd/polygonid
	cp $(IOS_OUT)/libpolygonid-darwin-arm64.h $(IOS_OUT)/libpolygonid.h

# Build a legacy multi-architecture version of libpolygonid.a with iOS Device arm64 & iOS Simulator x86_64
ios-old: ios-arm64 ios-simulator-x86_64
	lipo $(IOS_OUT)/libpolygonid-ios.a $(IOS_OUT)/libpolygonid-ios-simulator-x86_64.a -create -output $(IOS_OUT)/libpolygonid.a
	cp $(IOS_OUT)/libpolygonid-ios.h $(IOS_OUT)/libpolygonid.h

ios-simulator: ios-simulator-x86_64 ios-simulator-arm64
	lipo $(IOS_OUT)/libpolygonid-ios-simulator-x86_64.a $(IOS_OUT)/libpolygonid-ios-simulator-arm64.a -create -output $(IOS_OUT)/libpolygonid-ios-simulator.a
	cp $(IOS_OUT)/libpolygonid-ios-simulator-arm64.h $(IOS_OUT)/libpolygonid.h

ios: ios-old ios-arm64 ios-simulator

ios-static-xcframework: ios-arm64 ios-simulator darwin-arm64
	# Remove .xcframework if exists
	rm -rf $(IOS_OUT)/Iden3CLibrary.xcframework
	# Create separate folder with headers for xcframework
	mkdir -p $(IOS_OUT)/include
	cp $(IOS_OUT)/libpolygonid.h $(IOS_OUT)/include
	# Create xcframework from ios, sim and macos libs
	xcodebuild -create-xcframework \
    	-library $(IOS_OUT)/libpolygonid-ios.a -headers $(IOS_OUT)/include/ \
    	-library $(IOS_OUT)/libpolygonid-ios-simulator.a -headers $(IOS_OUT)/include/ \
    	-library $(IOS_OUT)/libpolygonid-darwin-arm64.a -headers $(IOS_OUT)/include/ \
    	-output $(IOS_OUT)/Iden3CLibrary.xcframework

ios-dynamic-xcframework: ios-arm64 ios-simulator darwin-arm64
	# Remove .xcframework if exists
	rm -rf $(IOS_OUT)/Iden3CLibrary.xcframework
	# Create iOS .dylib
	xcrun -sdk iphoneos clang -arch arm64 -fpic -shared -Wl,-all_load $(IOS_OUT)/libpolygonid-ios.a -framework Corefoundation -framework Security -o $(IOS_OUT)/libpolygonid-ios.dylib
	# Create iOS sim arm64 .dylib
	xcrun -sdk iphonesimulator clang -arch arm64 -fpic -shared -Wl,-all_load $(IOS_OUT)/libpolygonid-ios-simulator-arm64.a -framework Corefoundation -framework Security -o $(IOS_OUT)/libpolygonid-ios-simulator-arm64.dylib
	# Create iOS sim x86_64 .dylib
	xcrun -sdk iphonesimulator clang -arch x86_64 -fpic -shared -Wl,-all_load $(IOS_OUT)/libpolygonid-ios-simulator-x86_64.a -framework Corefoundation -framework Security -o $(IOS_OUT)/libpolygonid-ios-simulator-x86_64.dylib
	# Create iOS sim fat .dylib
	lipo $(IOS_OUT)/libpolygonid-ios-simulator-arm64.dylib $(IOS_OUT)/libpolygonid-ios-simulator-x86_64.dylib -output $(IOS_OUT)/libpolygonid-ios-simulator.dylib -create
	# Create macOS .dylib
	xcrun -sdk macosx clang -arch arm64 -fpic -shared -Wl,-all_load $(IOS_OUT)/libpolygonid-darwin-arm64.a -framework Corefoundation -framework Security -o $(IOS_OUT)/libpolygonid-darwin-arm64.dylib
	# Create separate folder with headers for xcframework
	mkdir -p $(IOS_OUT)/include
	cp $(IOS_OUT)/libpolygonid.h $(IOS_OUT)/include
	# Create xcframework from ios, sim and macos libs
	xcodebuild -create-xcframework \
 		-library $(IOS_OUT)/libpolygonid-ios.dylib -headers $(IOS_OUT)/include/ \
 		-library $(IOS_OUT)/libpolygonid-ios-simulator.dylib -headers $(IOS_OUT)/include/ \
 		-library $(IOS_OUT)/libpolygonid-darwin-arm64.dylib -headers $(IOS_OUT)/include/ \
 		-output $(IOS_OUT)/Iden3CLibrary.xcframework
 	# Set @rpath
	install_name_tool -id @rpath/libpolygonid-ios.dylib $(IOS_OUT)/Iden3CLibrary.xcframework/ios-arm64/libpolygonid-ios.dylib
	install_name_tool -id @rpath/libpolygonid-ios-simulator.dylib $(IOS_OUT)/Iden3CLibrary.xcframework/ios-arm64_x86_64-simulator/libpolygonid-ios-simulator.dylib
	install_name_tool -id @rpath/libpolygonid-darwin-arm64.dylib $(IOS_OUT)/Iden3CLibrary.xcframework/macos-arm64/libpolygonid-darwin-arm64.dylib


dylib:
	go build -tags prover_disabled -buildmode=c-shared -o $(IOS_OUT)/libpolygonid.dylib ./cmd/polygonid

ANDROID_OUT=android
ANDROID_NDK_HOME?=$(ANDROID_HOME)/ndk/22.1.7171670

android-armeabi-v7a:
	GOOS=android \
	GOARCH=arm \
	CGO_ENABLED=1 \
	CC=$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7a-linux-androideabi21-clang \
	go build -tags prover_disabled -buildmode=c-shared \
		-ldflags="-extldflags '-Wl,-z,max-page-size=0x4000'" \
		-o $(ANDROID_OUT)/jnilibs/armeabi-v7a/libpolygonid.so ./cmd/polygonid

android-arm64-v8a:
	GOOS=android \
	GOARCH=arm64 \
	CGO_ENABLED=1 \
	CC=$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android21-clang \
	go build -tags prover_disabled -buildmode=c-shared \
		-ldflags="-extldflags '-Wl,-z,max-page-size=0x4000'" \
		-o $(ANDROID_OUT)/jnilibs/arm64-v8a/libpolygonid.so ./cmd/polygonid

android-x86:
	GOOS=android \
	GOARCH=386 \
	CGO_ENABLED=1 \
	CC=$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/darwin-x86_64/bin/i686-linux-android21-clang \
	go build -tags prover_disabled -buildmode=c-shared \
		-ldflags="-extldflags '-Wl,-z,max-page-size=0x4000'" \
		-o $(ANDROID_OUT)/jnilibs/x86/libpolygonid.so ./cmd/polygonid

android-x86-64:
	GOOS=android \
	GOARCH=amd64 \
	CGO_ENABLED=1 \
	CC=$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/darwin-x86_64/bin/x86_64-linux-android21-clang \
	go build -tags prover_disabled -buildmode=c-shared \
		-ldflags="-extldflags '-Wl,-z,max-page-size=0x4000'" \
		-o $(ANDROID_OUT)/jnilibs/x86-64/libpolygonid.so ./cmd/polygonid

android-old: android-armeabi-v7a  android-x86

android-new: android-arm64-v8a android-x86-64

android: android-new android-old

all: android ios
