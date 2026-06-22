# @keepass-web/argon2

Argon2d and Argon2id key derivation function implementation for the [keepass-web](https://github.com/keepass-web) project.

Note: only the Argon2id and Argon2d variants are supported, because that's all that's required for KeePass. Argon2i is not implemented, consistent with RFC 9106, which requires only Argon2id.

## Specification

See [SPEC.md](./SPEC.md).

## Usage

Published to npm under the `@keepass-web` scope with provenance signing.

## Development

```sh
npm ci
npm run typecheck
npm run lint
npm test
```
