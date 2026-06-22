# Specification

## Argon2

Implemented per **RFC 9106** — *Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications* (September 2021).

- https://www.rfc-editor.org/rfc/rfc9106

Variants implemented: Argon2d and Argon2id.

- **Argon2d** — used by KDBX 4.x with the Argon2d KDF setting.
- **Argon2id** — used by KDBX 4.x with the Argon2id KDF setting.

Test vectors are taken from Appendix B of RFC 9106.
