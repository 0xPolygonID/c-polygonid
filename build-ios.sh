export GOOS=ios
export CGO_ENABLED=1
export CC=$(PWD)/clangwrap.sh
export CGO_CFLAGS="-fembed-bitcode"


if [ "$GOARCH" = "amd64" ]; then
    CLANGARCH="x86_64"
elif [ "$GOARCH" = "arm64" ]; then
    CLANGARCH="arm64"
fi
	

if [ "$SDK" = "iphoneos" ]; then
  export TARGET="$CLANGARCH-apple-ios$MIN_VERSION"
elif [ "$SDK" = "iphonesimulator" ]; then
  export TARGET="$CLANGARCH-apple-ios$MIN_VERSION-simulator"
fi

export SDK_PATH=$(xcrun --sdk "$SDK" --show-sdk-path)

export CGO_LDFLAGS="-target ${TARGET} -syslibroot \"${SDK_PATH}\""

if [ "$SDK" = "iphoneos" ]; then
    export LIB_FILE=ios/libpolygonid-ios-$CLANGARCH.a
elif [ "$SDK" = "iphonesimulator" ]; then
    export LIB_FILE=ios/libpolygonid-ios-sim-$CLANGARCH.a
fi

go build -buildmode c-archive -trimpath -o $LIB_FILE ./cmd/polygonid