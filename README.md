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

## Structure of Configuration

Some functions may require additional configuration.

```json5
{
  "ethereumUrl": "http://localhost:8545",
  // If we require the latest state for core.ID, we get it by calling this
  // contract.
  "stateContractAddr": "0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655",
  "reverseHashServiceUrl": "http://localhost:8003",
  // If we require the latest state for core.ID by contacting the contract, we
  // will initially search for it in this object. If the state is found, we will
  // not call the state contract and instead use this value.
  "lastStates": {
    "2qHrsSHq8RG9YzDkFUU7R8x5z8HjfEWuAzWCAEK6g5": "7924836296154662029985637624264388880357698768622974179372216832362758350725",
    "2qFuKxq6iPem5w2U6T6druwGFjqTinE1kqNkSN7oo9": "1731077184317746880604876415400072894642986932130192804318979776576650960989"
  },
  // This is a list of proofs. When we need to resolve a proof by making a call
  // to RHS, we first search for the proof in this array using the state and
  // revocation nonce values. If the proof is found here, we use it and don't
  // make a call to RHS.
  "proofs": [
    {
      "revocationNonce": 380518664,
      // instance of merkletree.Proof
      "proof": {
        "existence": true,
        "siblings": [
          "4160024929110510016837706240767461055576975198735514380169793693125931012555",
          "20060418938379981844865470860146694481548238498242410261462902127954246272447"
        ],
        "node_aux": {"key": "100500", "value": "0"}
      },
      // instance of circuits.TreeState
      "treeState": {
        "state": "1731077184317746880604876415400072894642986932130192804318979776576650960989",
        "claimsRoot": "6010518131296266678809565100594611581963235659253095687849925082119913660925",
        "revocationRoot": "0",
        "rootOfRoots": "10577450719885973132556528210032589552361029052981833196590877660483544191550"
      }
    }
  ]
}
```
