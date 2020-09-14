use libaes::Cipher;

#[test]
fn nist_verify() {
    // Verify the implementation's correctness using NIST data:
    // http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    // Appendix F.2 CBC Example Vectors
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
fn small_data() {
    // Encrypt and decrypt data that is smaller than 1 AES block size.
    let my_key = b"This is the key!"; // key is 16 bytes
    let cipher = Cipher::new_128(my_key);
    let plaintext = b"A plaintext"; // less than 16 bytes
    let iv = b"This is 16 bytes";
    let encrypted = cipher.cbc_encrypt(iv, plaintext);
    assert_eq!(encrypted.len(), 16); // Verify padding
    let decrypted = cipher.cbc_decrypt(iv, &encrypted[..]);
    assert_eq!(decrypted[..], plaintext[..]);
}
