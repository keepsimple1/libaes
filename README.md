# libaes

[![Build](https://github.com/keepsimple1/libaes/workflows/Build%20and%20Test/badge.svg)](https://github.com/keepsimple1/libaes/actions)

This is a re-implementation of OpenSSL 1.1.1 AES core algorithms in safe Rust, with zero dependencies.

My original motivation is to find a correct, fast and minimal AES library in Rust, so that I can easily use it to 
interact with an existing data system that uses AES. But I was not able to find such a library so I decided to
write one by porting AES core from [OpenSSL 1.1.1 stable](https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/aes/aes_core.c).
This library strives to be:

- Correct (as the original OpenSSL implementation)
- Fast (as OpenSSL 1.1.1)
- Safe Rust code only.
- Minimal: no dependencies.

In v0.1.0, this library only supports 128-bit key with CBC mode. Automatic padding is included.

## Examples

```rust
use libaes::Cipher;

let my_key = b"This is the key!"; // key is 16 bytes
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

We use a NIST test data to verify the cipher, see the [test code](tests/aes.rs).

## License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the above license(s), shall be
dual licensed as above, without any additional terms or conditions.
