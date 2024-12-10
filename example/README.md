# Example

This is an example demonstrating how to use the CLI.

## Generate a keypair

You already have an example keypair, so you can just skip this step.

```sh
rku new -n "Test Name" -e 2026-01-01
```

## Signing a file

This will sign **the hash** of `data.txt` file and output a signature file to `data.txt.sig`.

```sh
rku sign data.txt -k private_key -o data.txt.sig
```

## Verifying a file

This will verify the signature of the `data.txt` file using its hash.

```sh
rku verify data.txt -k public_key -s data.txt.sig # Output: Signature is valid
```

### Let's change the file contents and reverify

```sh
# Originally "Hello world!"
echo changed > data.txt
rku verify data.txt -k public_key -s data.txt.sig # Output: Signature is invalid
```

## Get information about your keys

```sh
rku key-info private_key
rku key-info public_key

# Output:
# 
# Type: ...
# Version: ..
#
# (...)
```

## Get information about a signature

```sh
rku signature-info data.txt.sig

# Output:
#
# Signed-By: ...
# Signature: ........
```

## Certify another key

If the client chooses to trust you, certifying *can* make it trust the other key too.

The example certifee key is already certified by the example key, you can just skip this step. Although recertifying it will not cause any harm.

```sh
rku certify certifee/public_key -k private_key
```

## Get information about a certification

```sh
rku certification-info certifee/public_key public_key

# Output:
# 
# Certified-By: ....
# Signature: ........
# Valid: true
```
