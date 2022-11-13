# c-polygonid

C wrapper for polygonid libraries.

## Build on macos M1

```shell
make darwin-arm64
```

## Run tests

```shell
cd examples
mkdir build
cd build
cmake ..
cmake --build .
make test
```

## Run example on Darwin M1

```shell
make darwin-arm64
cd examples
# `-framework CoreFoundation` is only for macOS
clang -L../build -lpolygonid-darwin-arm64 -framework CoreFoundation auth_v2_inputs.c && ./a.out
clang -L../build -lpolygonid-darwin-arm64 -framework CoreFoundation calculate_genesis_id.c && ./a.out
clang -L../build -lpolygonid-darwin-arm64 -framework CoreFoundation json_functions_tests.c && ./a.out
```
