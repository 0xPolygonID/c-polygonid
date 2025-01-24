# iden3comm

Golang implementation of iden3comm protocol

## Contributing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as below, without any additional terms or conditions.

## Build constraints

### no_jwz

If you do not use the JWZ functionality and do not need to run prover on
JWZ packed messages, you can build the library with the `no_jwz` build tag.
This build tag would prevent the dependency on the `librapidsnark.a` library

## License

&copy; 2023 0kims Association

This project is licensed under either of

- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE))
- [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT))

at your option.
