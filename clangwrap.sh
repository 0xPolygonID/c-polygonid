#!/bin/sh
# To select a specific SDK, run 'xcodebuild -showsdks'
# You need to specify SDK & CLANGARCH

SDK_PATH=`xcrun --sdk $SDK --show-sdk-path`
export IPHONEOS_DEPLOYMENT_TARGET=5.1
# cmd/cgo doesn't support llvm-gcc-4.2, so we have to use clang.
CLANG=`xcrun --sdk $SDK --find clang`

exec "$CLANG" -arch $CLANGARCH -isysroot "$SDK_PATH" -mios-version-min=10.0 "$@"
