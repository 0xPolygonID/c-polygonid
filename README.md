# c-polygonid

This is a wrapper library for several PolygonID Go libraries, designed for use
with C/C++ languages. It can also be used in mobile development or other
infrastructures facing challenges with Go integration.

An overview of the major functions looks like this:
```
GoUint8 PLGNAtomicQuerySigV2Inputs(char** jsonResponse, char* jsonRequest, char* cfg, PLGNStatus** status);
```

`GoUint8` is a type alias for `signed char`, which essentially represents a Go
bool. It can be `0` or `1`. Generally, the function returns `1` in the event of
a successful operation and `0` in the event of failure.

If the `status` pointer is not NULL, a new PLGNStatus object will be allocated,
containing details about errors. This object should be freed with the
`PLGNStatusFree` function to avoid a memory leak.

`jsonRequest` and `jsonResponse` are plain JSON objects. Their contents depend
on the specific function and should be documented in the
[polygonid.go](cmd/polygonid/polygonid.go) file. The examples of requests to
different functions can be found in [testdata](testdata) directory.

## Configuration

The configuration object is a JSON document with the following structure:
```json5
{
  "ipfsNodeUrl": "http://localhost:5001", // IPFS Node URL
  "didMethods": [
    {
      "name": "ethr",           // DID method name
      "blockchain": "ethereum", // Blockchain name
      "network": "mainnet",     // Network name
      "networkFlag": 6,         // Network flag
      "methodByte": "0b010011", // Method byte
      "chainID": "10293"
    }
  ],
  "chainConfigs": {
    "1": { // Chain ID as decimal
      "rpcUrl": "http://localhost:8545", // RPC URL
      "stateContractAddr": "0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655" // State contract address
    },
    "0x10": { // Chain ID in hexadecimal format
      "rpcUrl": "http://localhost:8545",
      "stateContractAddr": "0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655"
    }
  },
  // Directory to cache time-consuming operations.
  // If empty, use the default one in user's HOME directory.
  "cacheDir": "/tmp/polygonid"
}
```

This object should be passed on each call to the library.
It is not memorized or cached.

## Errors

In case of an error, the function returns `0`, and if the pointer to the
`PLGNStatus` struct is not NULL, a struct object will be allocated and filled
with the following structure:

```C
typedef struct _PLGNStatus
{
	PLGNStatusCode status;
	char *error_msg;
} PLGNStatus;
```

Here, `PLGNStatusCode` is the status enum that can be seen in the .h file
included in the distribution of this library, and `error_msg` is a string
containing a detailed, human-readable error.

This object should be freed with `PLGNStatusFree` function.

## Build on macos M1

```shell
make darwin-arm64
```

## Build for iOS device

```shell
make ios
```

The Makefile includes several iOS-specific targets for building the library 
for iOS devices. Here is the list of all targets and the libraries that
will be built:

| Target                    | File | Description                                                                                            | 
|---------------------------| --- |--------------------------------------------------------------------------------------------------------|
| **ios-arm64**             | ios/libpolygonid-ios.a | iOS Device arm64 architecture                                                                          |
| **ios-simulator-x86_64**  | ios/libpolygonid-ios-simulator-x86_64 | iOS Simulator x86_64 architecture                                                                      |
| **ios-simulator-arm64**   | ios/libpolygonid-ios-simulator-arm64 | iOS Simulator arm64 architecture                                                                       |
| **ios-old**               | ios/libpolygonid.a | a universal binary that includes two architectures:<br>- iOS Device arm64<br>- iOS Simulator x86_64    |
| **ios-simulator**         | ios/libpolygonid-ios-simulator.a | a universal binary that includes two architectures:<br>- iOS Simulator x86_64<br>- iOS Simulator arm64 |
| **ios**                   | | Build everything above                                                                                 |

After each build target there will be an `ios/libpolygonid.h` header file.

## Run tests

The library build be built with previous command. And copy it to `ios/libpolygonid.a` file.
For example.
```shell
make darwin-arm64
cp ios/libpolygonid-darwin-arm64.a ios/libpolygonid.a
```

Then you can build and run tests.

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
