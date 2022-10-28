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
clang -L../build -lpolygonid-darwin-arm64 auth_v2_inputs.c && ./a.out
```
