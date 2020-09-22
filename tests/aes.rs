use libaes::Cipher;

#[test]
fn nist_verify_aes_128_cbc() {
    // Verify the implementation's correctness using NIST Special Publication 800-38A:
    // http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    // Appendix F.2.1 and F.2.2 CBC Example Vectors
    const NIST_CBC_KEY: &[u8; 16] =
        b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";
    let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    let plaintext = b"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\
                           \xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\
                           \x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\
                           \xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10";
    let ciphertext = b"\x76\x49\xab\xac\x81\x19\xb2\x46\xce\xe9\x8e\x9b\x12\xe9\x19\x7d\
                           \x50\x86\xcb\x9b\x50\x72\x19\xee\x95\xdb\x11\x3a\x91\x76\x78\xb2\
                           \x73\xbe\xd6\xb8\xe3\xc1\x74\x3b\x71\x16\xe6\x9e\x22\x22\x95\x16\
                           \x3f\xf1\xca\xa1\x68\x1f\xac\x09\x12\x0e\xca\x30\x75\x86\xe1\xa7";

    let cipher = Cipher::new_128(NIST_CBC_KEY);
    let encrypted = cipher.cbc_encrypt(iv, plaintext);
    let len_without_padding = 16 * 4;
    let padding_size = 16;
    assert_eq!(encrypted.len(), len_without_padding + padding_size);
    assert_eq!(encrypted[..len_without_padding], ciphertext[..]);

    let decrypted = cipher.cbc_decrypt(iv, &encrypted[..]);
    assert_eq!(decrypted[..], plaintext[..]);
}

#[test]
fn nist_verify_aes_192_cbc() {
    // Verify the implementation's correctness using NIST Special Publication 800-38A:
    // http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    // Appendix F.2.3 and F.2.4 CBC Example Vectors for 192-bit
    const NIST_CBC_KEY: &[u8; 24] =
        b"\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\
        \x62\xf8\xea\xd2\x52\x2c\x6b\x7b";
    let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    let plaintext  = b"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\
                       \xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\
                       \x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\
                       \xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10";
    let ciphertext = b"\x4f\x02\x1d\xb2\x43\xbc\x63\x3d\x71\x78\x18\x3a\x9f\xa0\x71\xe8\
                       \xb4\xd9\xad\xa9\xad\x7d\xed\xf4\xe5\xe7\x38\x76\x3f\x69\x14\x5a\
                       \x57\x1b\x24\x20\x12\xfb\x7a\xe0\x7f\xa9\xba\xac\x3d\xf1\x02\xe0\
                       \x08\xb0\xe2\x79\x88\x59\x88\x81\xd9\x20\xa9\xe6\x4f\x56\x15\xcd";
    let cipher = Cipher::new_192(NIST_CBC_KEY);
    let encrypted = cipher.cbc_encrypt(iv, plaintext);
    let len_without_padding = 16 * 4;
    let padding_size = 16;
    assert_eq!(encrypted.len(), len_without_padding + padding_size);
    assert_eq!(encrypted[..len_without_padding], ciphertext[..]);

    let decrypted = cipher.cbc_decrypt(iv, &encrypted[..]);
    assert_eq!(decrypted[..], plaintext[..]);
}

#[test]
fn nist_verify_aes_256_cbc() {
    // Verify the implementation's correctness using NIST Special Publication 800-38A:
    // http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    // Appendix F.2.5 and F.2.6 CBC Example Vectors
    const NIST_CBC_KEY: &[u8; 32] =
        b"\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\
          \x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4";
    let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    let plaintext  = b"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\
                       \xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\
                       \x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\
                       \xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10";
    let ciphertext = b"\xf5\x8c\x4c\x04\xd6\xe5\xf1\xba\x77\x9e\xab\xfb\x5f\x7b\xfb\xd6\
                       \x9c\xfc\x4e\x96\x7e\xdb\x80\x8d\x67\x9f\x77\x7b\xc6\x70\x2c\x7d\
                       \x39\xf2\x33\x69\xa9\xd9\xba\xcf\xa5\x30\xe2\x63\x04\x23\x14\x61\
                       \xb2\xeb\x05\xe2\xc3\x9b\xe9\xfc\xda\x6c\x19\x07\x8c\x6a\x9d\x1b";
    let cipher = Cipher::new_256(NIST_CBC_KEY);
    let encrypted = cipher.cbc_encrypt(iv, plaintext);
    let len_without_padding = 16 * 4;
    let padding_size = 16;
    assert_eq!(encrypted.len(), len_without_padding + padding_size);
    assert_eq!(encrypted[..len_without_padding], ciphertext[..]);

    let decrypted = cipher.cbc_decrypt(iv, &encrypted[..]);
    assert_eq!(decrypted[..], plaintext[..]);
}

#[test]
fn small_data() {
    // Encrypt and decrypt data that is smaller than 1 AES block size.
    let my_key = b"This is the key!"; // key is 16 bytes
    let cipher = Cipher::new_128(my_key);
    let plaintext = b"A plaintext"; // less than 16 bytes
    let iv = b"This is 16 bytes";
    let encrypted_128 = cipher.cbc_encrypt(iv, plaintext);
    assert_eq!(encrypted_128.len(), 16); // Verify padding
    let decrypted_128 = cipher.cbc_decrypt(iv, &encrypted_128[..]);
    assert_eq!(decrypted_128[..], plaintext[..]);

    // Test with AES-256
    let key_256 = b"This is the key!This is the key!";
    let cipher = Cipher::new_256(key_256);
    let encrypted_256 = cipher.cbc_encrypt(iv, plaintext);
    assert_eq!(encrypted_256.len(), 16); // Verify padding
    assert_ne!(encrypted_256[..], encrypted_128[..]); // Verify AES-256 is different from AES-128
    let decrypted_256 = cipher.cbc_decrypt(iv, &encrypted_256[..]);
    assert_eq!(decrypted_256[..], plaintext[..]);

    // Test with AES-192
    let key_192 = b"This is the key! 192 bit";
    let cipher = Cipher::new_192(key_192);
    let encrypted_192 = cipher.cbc_encrypt(iv, plaintext);
    assert_eq!(encrypted_192.len(), 16); // Verify padding
    assert_ne!(encrypted_192[..], encrypted_256[..]); // Verify AES-192 is different from AES-256
    let decrypted_192 = cipher.cbc_decrypt(iv, &encrypted_192[..]);
    assert_eq!(decrypted_192[..], plaintext[..]);
}

#[test]
fn large_data() {
    // Encrypt and decrypt data that is larger than 10 blocks.
    let key_128 = b"This is the key!";
    let iv = b"This is 16 bytes";
    let plaintext = b"The Road Not Taken - by Robert Frost\
                    Two roads diverged in a yellow wood,\
                    And sorry I could not travel both\
                    And be one traveler, long I stood\
                    And looked down one as far as I could\
                    To where it bent in the undergrowth;\
                    Then took the other, as just as fair,\
                    And having perhaps the better claim,\
                    Because it was grassy and wanted wear;\
                    Though as for that the passing there\
                    Had worn them really about the same,\
                    And both that morning equally lay\
                    In leaves no step had trodden black.\
                    Oh, I kept the first for another day!\
                    Yet knowing how way leads on to way,\
                    I doubted if I should ever come back.\
                    I shall be telling this with a sigh\
                    Somewhere ages and ages hence:\
                    Two roads diverged in a wood, and I\
                    I took the one less traveled by,\
                    And that has made all the difference.";
    let cipher = Cipher::new_128(key_128);
    let encrypted_128 = cipher.cbc_encrypt(iv, plaintext);
    let decrypted_128 = cipher.cbc_decrypt(iv, &encrypted_128[..]);
    assert_eq!(decrypted_128[..], plaintext[..]);

    // Test with AES-256
    let key_256 = b"This is the key!This is the key!";
    let cipher = Cipher::new_256(key_256);
    let encrypted_256 = cipher.cbc_encrypt(iv, plaintext);
    assert_eq!(encrypted_256.len(), encrypted_128.len());
    assert_ne!(encrypted_256[..], encrypted_128[..]);
    let decrypted_256 = cipher.cbc_decrypt(iv, &encrypted_256[..]);
    assert_eq!(decrypted_256[..], plaintext[..]);

    // Test with AES-192
    let key_192 = b"This is the key! 192 bit";
    let cipher = Cipher::new_192(key_192);
    let encrypted_192 = cipher.cbc_encrypt(iv, plaintext);
    assert_eq!(encrypted_192.len(), encrypted_256.len());
    assert_ne!(encrypted_192[..], encrypted_256[..]);
    let decrypted_192 = cipher.cbc_decrypt(iv, &encrypted_192[..]);
    assert_eq!(decrypted_192[..], plaintext[..]);
}
