# merkletree-proof
Merkletree proof is a complementary library for [reverse hash service](https://github.com/iden3/reverse-hash-service) to
fetch iden3 identity state roots and generate [Sparse Merkle Tree proofs](https://github.com/iden3/go-merkletree-sql). 

## Docs

- [https://docs.iden3.io](https://docs.iden3.io/services/rhs/)
- [Sparce Merkle Tree](https://docs.iden3.io/publications/pdfs/Merkle-Tree.pdf)
- [go-merkletree-sql](https://github.com/iden3/go-merkletree-sql)

## Install

`go get github.com/iden3/go-merkletree-proof`

## Examples

### Fetch identity state roots

Fetch identity state roots for identity state hash `e12084d0d72c492c703a2053b371026bceda40afb9089c325652dfd2e5e11223`
Identity state must be fetched from the blockchain [State contract](https://docs.iden3.io/contracts/state/).

```go
stateHash, _ := merkletree.NewHashFromHex("e12084d0d72c492c703a2053b371026bceda40afb9089c325652dfd2e5e11223")

cli := &merkletree_proof.HTTPReverseHashCli{URL: "<link to RHS>"}
// get identity state roots

stateValues, err := cli.GetNode(ctx, stateHash)
```

### Generate proof

Generate proof for revocation nonce `670966937` and revocation root `b92f062026083232bdd4d3a93986276515aa874fd3f7e928d6f67c8c91a6b705`

```go
revocationNonce, _ := merkletree.NewHashFromBigInt(big.NewInt(670966937))
revocationRoot, _ := merkletree.NewHashFromHex("b92f062026083232bdd4d3a93986276515aa874fd3f7e928d6f67c8c91a6b705")

cli := &proof.HTTPReverseHashCli{URL: "<link to RHS>"}
proof, _ := cli.GenerateProof(ctx, revocationRoot, revocationNonce)
```

## Contributing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as below, without any additional terms or conditions.

## License

Copyright 2023 0kims Association

This project is licensed under either of

- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE))
- [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT))

at your option.
