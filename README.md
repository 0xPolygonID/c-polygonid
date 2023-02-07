# c-polygonid

C wrapper for polygonid libraries.

## Build on macos M1

```shell
make darwin-arm64
```

## Run tests

The library build be built with previous command.

```shell
cd examples
mkdir build
cd build
cmake ..
cmake --build .
make test ARGS="--rerun-failed --output-on-failure"
```

## Run example on Darwin M1

```shell
make darwin-arm64
cd examples
# `-framework CoreFoundation -framework Security` is only for macOS
clang -L../ios -lpolygonid-darwin-arm64 -framework CoreFoundation -framework Security -framework CoreServices json_functions_tests.c && ./a.out
```
