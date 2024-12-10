#! /usr/bin/env bun

import { readFileSync, writeFileSync } from 'fs'
import { program } from 'commander'

import { createRevengeKeyPair, readRevengeKey, readRevengeSignature } from './src/v1'
import { KeyType } from './src/shared'
import { toHex } from './src/utils'

program.name('revenge-keyutil').description('Utilities for working with Revenge keys')

program
    .command('new')
    .alias('n')
    .requiredOption('-n, --name <name>', 'Name of keypair')
    .requiredOption('-e, --expires <date>', 'Key expiration date')
    .option('-pr, --private-key-path <path>', 'Path to private key', './private_key')
    .option('-pb, --public-key-path <path>', 'Path to public key', './public_key')
    .action(({ name, expires, privateKeyPath, publicKeyPath }) => {
        const { privateKey, publicKey } = createRevengeKeyPair({
            name,
            expires: BigInt(Math.floor(new Date(expires).getTime() / 1000)),
        })

        writeFileSync(privateKeyPath, Buffer.from(privateKey.toArrayBuffer()))
        writeFileSync(publicKeyPath, Buffer.from(publicKey.toArrayBuffer()))

        console.log(`Saved private key to ${privateKeyPath} and public key to ${publicKeyPath}`)
    })

program
    .command('sign')
    .alias('s')
    .argument('<file>', 'Path to file')
    .requiredOption('-s, --signature, -o, --output <path>', 'Path to signature')
    .requiredOption('-k, -pr, --private-key-path, --key-path <path>', 'Path to private key of the signer')
    .action((filePath, { signature: signatureFilePath, Pr: keyPath }) => {
        const file = readFileSync(filePath)
        const key = readRevengeKey(readFileSync(keyPath).buffer as ArrayBuffer)

        if (!key.isPrivate()) throw new Error('Key must be a private key')

        const signature = key.sign(file)
        writeFileSync(signatureFilePath, Buffer.from(signature.toArrayBuffer()))

        console.log(`Signed ${filePath} and saved signature to ${signatureFilePath}`)
    })

program
    .command('verify')
    .alias('v')
    .argument('<file>', 'Path to file')
    .requiredOption('-s, --signature, -o, --output <path>', 'Path to signature')
    .requiredOption('-k, -pb, --public-key-path, --key-path <path>', 'Path to public key of the signer')
    .action((filePath, { signature: signatureFilePath, Pb: keyPath }) => {
        const file = readFileSync(filePath)
        const signature = readRevengeSignature(readFileSync(signatureFilePath).buffer as ArrayBuffer)
        const key = readRevengeKey(readFileSync(keyPath).buffer as ArrayBuffer)

        if (!key.isPublic()) throw new Error('Key must be a public key')

        const isValid = key.verify(signature.signature, file)
        console.log(`Signature is ${isValid ? 'valid' : 'invalid'}`)
    })

program
    .command('key-info')
    .aliases(['ki', 'keyinfo', 'kinfo'])
    .argument('<path>', 'Path to key/signature file')
    .action(keyPath => {
        const file = readFileSync(keyPath)
        const key = readRevengeKey(file.buffer as ArrayBuffer)

        console.log('')
        console.log(`Type: ${KeyType[key.type]}`)
        console.log('Version:', key.version)
        console.log('')

        if (key.isPublic()) {
            console.log(`Name: ${key.info.name}`)
            console.log(`ID: ${key.id}`)
            console.log(
                'Expires:',
                new Date(Number(key.info.expires) * 1000).toISOString(),
                `(${key.expired ? 'expired' : 'valid'})`,
            )
            console.log('')
            console.log(`Signature: ${toHex(key.signature)}`)
            console.log('Self-Signed:', !!key.certifications[key.id]?.isValid(key.key))
        } else {
            console.log(`Name: ${key.info.publicKeyInfo.name}`)
            console.log(`ID: ${key.id}`)
            console.log(
                'Expires:',
                new Date(Number(key.info.publicKeyInfo.expires) * 1000).toISOString(),
                `(${key.expired ? 'expired' : 'valid'})`,
            )
            console.log('')
            console.log(`Public-ID: ${key.publicId}`)
        }
    })

program
    .command('signature-info')
    .aliases(['si', 'signatureinfo', 'sig-info', 'siginfo', 'sinfo'])
    .argument('<path>', 'Path to signature file')
    .action(path => {
        const file = readFileSync(path)
        const signature = readRevengeSignature(file.buffer as ArrayBuffer)

        console.log('')
        console.log(`Signed-By: ${signature.signerPublicId}`)
        console.log(`Signature: ${toHex(signature.signature)}`)
    })

program.parse()
