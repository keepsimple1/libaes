# libaes

[![Build](https://github.com/keepsimple1/libaes/workflows/Build%20and%20Test/badge.svg)](https://github.com/keepsimple1/libaes/actions)
[![Cargo](https://img.shields.io/crates/v/libaes.svg)](https://crates.io/crates/libaes)

This is a small implementation of AES in safe Rust, with no dependencies. The core algorithm is ported
from AES core of [OpenSSL 1.1.1 stable](https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/aes/aes_core.c).
It is hardware-independent and fast (for example, as of January 2021, its AES-128 CBC mode is more than 3X faster than
RustCrypto [`aes`](https://crates.io/crates/aes) + [`block-modes`](https://crates.io/crates/block-modes) crates,
see [benchmark](https://github.com/keepsimple1/libaes-utils/blob/main/README.md#Benchmark)).

Currently, this library supports:

- CBC mode: 128-bit, 192-bit and 256-bit keys
- CFB128 mode

See [Documentation](https://docs.rs/libaes/) for examples and [tests](tests).

## Correctness

We use the test data in NIST Special Publication 800-38A to verify the cipher, see the [test code](tests/aes.rs).

## Minimum Rust version

Tested against Rust 1.46.0

## License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Contributions are welcome! Please open an issue in GitHub if any questions.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the above license(s), shall be
dual licensed as above, without any additional terms or conditions.
