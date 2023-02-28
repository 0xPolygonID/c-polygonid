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

## Generate StateV2 contract ABI
The contract can be found in a different repository located at
https://github.com/iden3/contracts. To generate the StateV2.go file again, you
need `abigen` command installed from
https://github.com/ethereum/go-ethereum/tree/master/cmd/abigen.
Then it is required to run following commands from `contracts` repository
```bash
npm install
# Compile the contracts. After this command file
# artifacts/contracts/state/StateV2.sol/StateV2.json should appear.
# E2E_PUBLISHING_KEY env is required but not used, so we can put anything
# in it.
E2E_PUBLISHING_KEY=1111111111111111111111111111111111111111111111111111111111111111 npm run compile
# Extract bytecode from compiled artifacts to StateV2.bcode file
jq -r .bytecode artifacts/contracts/state/StateV2.sol/StateV2.json > StateV2.bcode
# Extract ABI from compiled artifacts to StateV2.abi file
jq .abi artifacts/contracts/state/StateV2.sol/StateV2.json > StateV2.abi
# Generate Go package from ABI.
`go env GOPATH`/bin/abigen --bin=StateV2.bcode --abi=StateV2.abi --pkg=c_polygonid --out=../c-polygonid/StateV2.go
```
