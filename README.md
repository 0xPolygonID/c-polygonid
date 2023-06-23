# c-polygonid

C wrapper for polygonid libraries.

## Build on macos M1

```shell
make darwin-arm64
```

## Run tests

The library build be built with previous command.

```shell
mkdir examples/build
cd examples/build
cmake ..
cmake --build .
make test ARGS="--rerun-failed --output-on-failure"
```

## Run example on Darwin M1

```shell
brew install cjson
make darwin-arm64
cd examples
clang -L../ios -lpolygonid-darwin-arm64 \
        -framework CoreFoundation \
        -framework Security \
        -framework CoreServices \
        `pkg-config --libs --cflags libcjson` \
        json_functions_tests.c && ./a.out
```