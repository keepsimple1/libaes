# Version 0.7.0
No breaking changes. Bumped the minor version because of a new API of padding.

- support changing auto_padding setting in CBC mode (#30)

# Version 0.6.5
- Handles empty data gracefully in unpad() (#22)
- Fix build warnings in recent Rust 1.69 (#23)
- Add a test case for empty data in CBC (#24)

# Version 0.6.4
- Enable cargo fmt check (#19)

# Version 0.6.3
- check input length in decrypt (#17)

# Verison 0.6.2
- add keyword and category (#15)

# Version 0.6.1
- Fix a typo

# Version 0.6.0
- Reverse API change in 0.5.0

# Version 0.5.0
- API change: return an error type for cbc_decrypt
- Update README

# Version 0.4.0

- Add support for CFB128 mode

# Version 0.3.0

- Add support for 192-bit keys

# Version 0.2.0

- Add support for 256-bit keys

# Version 0.1.2

- Add missing crates.io doc link

# Version 0.1.1

- Add missing fields in Cargo publish

# Version 0.1.0

- Initial version
