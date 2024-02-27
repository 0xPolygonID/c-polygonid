#!/bin/sh
# To select a specific SDK, run 'xcodebuild -showsdks'
# You need to specify SDK

SDK_PATH=`xcrun --sdk $SDK --show-sdk-path`
CLANG=`xcrun --sdk $SDK --find clang`

exec "$CLANG" -target "$TARGET" -isysroot "$SDK_PATH" "$@"
