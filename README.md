# libaes

[![Build](https://github.com/keepsimple1/libaes/workflows/Build%20and%20Test/badge.svg)](https://github.com/keepsimple1/libaes/actions)
[![Cargo](https://img.shields.io/crates/v/libaes.svg)](https://crates.io/crates/libaes)

This is a re-implementation of AES in safe Rust, with zero dependencies. The core algorithm is ported
from AES core in [OpenSSL 1.1.1 stable](https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/aes/aes_core.c).
This library strives to be:

- Correct (as the original OpenSSL implementation)
- Fast (as OpenSSL 1.1.1)
- Safe Rust code only.
- Small: no dependencies.

Currently, this library supports 128-bit, 192-bit and 256-bit keys with CBC mode and CFB128 mode.

## Examples

```rust
use libaes::Cipher;

let my_key = b"This is the key!"; // key is 128-bit (16 bytes)
let plaintext = b"A plaintext";
let iv = b"This is 16 bytes";

// Create a new cipher
let cipher = Cipher::new_128(my_key);

// Encryption
let encrypted = cipher.cbc_encrypt(iv, plaintext);

// Decryption
let decrypted = cipher.cbc_decrypt(iv, &encrypted[..]);

```

## Correctness

We use the test data in NIST Special Publication 800-38A to verify the cipher, see the [test code](tests/aes.rs).

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
