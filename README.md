# rfc-8439

This is a working implementation of "RFC 8439: ChaCha20 and Poly1305 for IETF
Protocols", written in Common Lisp. It passes the primary test vectors given in
the RFC.

The main functions mimick the RFC's pseudocode:

```
;; (aad: u8[], key: u8[32], iv: u8[8], constant: u8[4], plaintext: u8[]) => u8[], u8[16]
(chacha20-aead-encrypt aad key iv constant plaintext)
```
and
```
;; (aad: u8[], key: u8[32], iv: u8[8], constant: u8[4], ciphertext: u8[]) => u8[], u8[16]
(chacha20-aead-decrypt aad key iv constant ciphertext)
```

`iv` and `constant` get concatenated, forming a 96-bit nonce. The typical way
to use this cipher is to set said nonce to `1` and increase by `1` after each
message encrypted. A counter value MUST NOT ever be reused with the same key.

# Disclaimer
This was a fun little educational project, and hasn't been audited. Please
don't use it for real software that affects people's lives. It also hasn't been
optimized for speed.

# License
AGPL-3.0

