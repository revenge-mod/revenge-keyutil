# Revenge Key Utilities

Revenge keys are used to sign and verify data. It is very much inspired by GPG, but has less features and a different file format.

## Specification

- [Version 1](./specs/v1.md)

## Why not GPG?

GPG is great, but there aren't any known GPG/PGP libraries that work under React Native without any native code. Our format is also much simpler meaning it's easier to implement and adds less size to our JS bundle.

## Using the CLI

1. Install [Bun](https://bun.sh)
2. Install the package

   ```sh
   bun install https://github.com/revenge-mod/revenge-keyutil
   ```

3. Run the CLI

   ```sh
   revenge-keyutil
   ```

### Example

Check the [example](./example) directory.

## Licence

This project is licensed under the [MIT Licence](./LICENSE).
